// Package validator checks service account tokens with the TokenReview API.
package validator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/arndt-s/wag-k8s/internal/wag"
)

const (
	saUserPrefix = "system:serviceaccount:"

	extraPodName  = "authentication.kubernetes.io/pod-name"
	extraPodUID   = "authentication.kubernetes.io/pod-uid"
	extraNodeName = "authentication.kubernetes.io/node-name"

	maxCacheEntries = 10000
)

// TokenReview validates service account tokens by asking the API server. It
// only accepts tokens minted for one of its audiences, and caches successful
// reviews for at most cacheTTL.
type TokenReview struct {
	client    kubernetes.Interface
	audiences []string
	cacheTTL  time.Duration
	now       func() time.Time

	mu    sync.Mutex
	cache map[[32]byte]cacheEntry
}

type cacheEntry struct {
	id      *wag.Identity
	expires time.Time
}

func NewTokenReview(client kubernetes.Interface, audiences []string, cacheTTL time.Duration) *TokenReview {
	return &TokenReview{
		client:    client,
		audiences: audiences,
		cacheTTL:  cacheTTL,
		now:       time.Now,
		cache:     map[[32]byte]cacheEntry{},
	}
}

// ErrUnavailable means the token could not be checked, as opposed to being bad.
var ErrUnavailable = errors.New("token review unavailable")

func (v *TokenReview) Validate(ctx context.Context, token string) (*wag.Identity, error) {
	now := v.now()
	// The cache key is a hash, so tokens are never held in memory longer than
	// the request.
	key := sha256.Sum256([]byte(token))
	if id, ok := v.lookup(key, now); ok {
		cacheHits.Inc()
		return id, nil
	}

	exp, err := unverifiedExpiry(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", wag.ErrInvalidToken, err)
	}
	if !exp.After(now) {
		return nil, fmt.Errorf("%w: token expired", wag.ErrInvalidToken)
	}

	tr, err := v.client.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: v.audiences},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	st := tr.Status
	if !st.Authenticated {
		msg := st.Error
		if msg == "" {
			msg = "not authenticated"
		}
		return nil, fmt.Errorf("%w: %s", wag.ErrInvalidToken, msg)
	}
	if !slices.ContainsFunc(st.Audiences, func(a string) bool { return slices.Contains(v.audiences, a) }) {
		return nil, fmt.Errorf("%w: token is not for audience %v", wag.ErrInvalidToken, v.audiences)
	}
	id, err := identityFrom(st.User)
	if err != nil {
		return nil, err
	}
	// The expiry was read before review; it is trusted now that the API
	// server accepted the token.
	id.ExpiresAt = exp
	v.store(key, id, now)
	return id, nil
}

func identityFrom(u authnv1.UserInfo) (*wag.Identity, error) {
	rest, ok := strings.CutPrefix(u.Username, saUserPrefix)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a service account", wag.ErrInvalidToken, u.Username)
	}
	ns, sa, ok := strings.Cut(rest, ":")
	if !ok || ns == "" || sa == "" || u.UID == "" {
		return nil, fmt.Errorf("%w: malformed service account user %q", wag.ErrInvalidToken, u.Username)
	}
	extra := make(map[string][]string, len(u.Extra))
	for k, vs := range u.Extra {
		extra[k] = append([]string(nil), vs...)
	}
	first := func(k string) string {
		if vs := extra[k]; len(vs) > 0 {
			return vs[0]
		}
		return ""
	}
	return &wag.Identity{
		Namespace:         ns,
		ServiceAccount:    sa,
		ServiceAccountUID: u.UID,
		PodName:           first(extraPodName),
		PodUID:            first(extraPodUID),
		NodeName:          first(extraNodeName),
		Extra:             extra,
	}, nil
}

// unverifiedExpiry reads exp from a JWT without checking its signature. The
// caller must only trust it after TokenReview accepted the token.
func unverifiedExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, errors.New("token is not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, errors.New("token payload is not base64url")
	}
	var claims struct {
		Exp *json.Number `json:"exp"`
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return time.Time{}, errors.New("token payload is not JSON")
	}
	if claims.Exp == nil {
		return time.Time{}, errors.New("token has no exp")
	}
	exp, err := claims.Exp.Int64()
	if err != nil {
		return time.Time{}, errors.New("token exp is not an integer")
	}
	return time.Unix(exp, 0), nil
}

func (v *TokenReview) lookup(key [32]byte, now time.Time) (*wag.Identity, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[key]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expires) {
		delete(v.cache, key)
		return nil, false
	}
	return e.id, true
}

func (v *TokenReview) store(key [32]byte, id *wag.Identity, now time.Time) {
	if v.cacheTTL <= 0 {
		return
	}
	expires := now.Add(v.cacheTTL)
	if id.ExpiresAt.Before(expires) {
		expires = id.ExpiresAt
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= maxCacheEntries {
		for k, e := range v.cache {
			if !now.Before(e.expires) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= maxCacheEntries {
			return
		}
	}
	v.cache[key] = cacheEntry{id: id, expires: expires}
}
