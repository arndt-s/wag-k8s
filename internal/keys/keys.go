// Package keys holds signing key sets and where they are stored.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// State is where a key is in its rotation lifecycle.
type State string

const (
	// StateNext keys are published but do not sign yet.
	StateNext State = "next"
	// StateCurrent is the one key that signs.
	StateCurrent State = "current"
	// StatePrevious keys no longer sign but stay published until grants they
	// signed have expired and caches have caught up.
	StatePrevious State = "previous"
)

// Key is one signing key with its private part.
type Key struct {
	ID             string          `json:"kid"`
	State          State           `json:"state"`
	CreatedAt      time.Time       `json:"createdAt"`
	StateChangedAt time.Time       `json:"stateChangedAt"`
	JWK            jose.JSONWebKey `json:"jwk"`
}

// KeySet is everything a KeyStore holds.
type KeySet struct {
	Keys []Key `json:"keys"`
	// Version identifies what was loaded, for compare-and-swap on Save.
	Version string `json:"-"`
}

// KeyStore loads and saves a KeySet. Only the rotation job saves.
type KeyStore interface {
	// Load returns wag.ErrNotFound when no key set exists yet.
	Load(ctx context.Context) (*KeySet, error)
	// Save is compare-and-swap on version; version "" creates the key set.
	// It returns wag.ErrConflict when the stored key set changed.
	Save(ctx context.Context, ks *KeySet, version string) error
}

// Watcher is implemented by stores that can push changes instead of being polled.
type Watcher interface {
	// Watch calls fn with every new key set until ctx is done.
	Watch(ctx context.Context, fn func(*KeySet)) error
}

// Current returns the signing key, or nil when there is none.
func (ks *KeySet) Current() *Key {
	if ks == nil {
		return nil
	}
	for i := range ks.Keys {
		if ks.Keys[i].State == StateCurrent {
			return &ks.Keys[i]
		}
	}
	return nil
}

// PublicJWKS returns the public parts of all keys, for publishing.
func (ks *KeySet) PublicJWKS() jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	if ks == nil {
		return set
	}
	for _, k := range ks.Keys {
		set.Keys = append(set.Keys, k.JWK.Public())
	}
	return set
}

// Validate checks that the key set is usable for signing.
func (ks *KeySet) Validate() error {
	current := 0
	seen := map[string]bool{}
	for _, k := range ks.Keys {
		if seen[k.ID] {
			return fmt.Errorf("duplicate kid %q", k.ID)
		}
		seen[k.ID] = true
		if k.JWK.KeyID != k.ID {
			return fmt.Errorf("key %q: jwk kid %q does not match", k.ID, k.JWK.KeyID)
		}
		if k.JWK.IsPublic() || !k.JWK.Valid() {
			return fmt.Errorf("key %q: not a valid private key", k.ID)
		}
		switch k.State {
		case StateCurrent:
			current++
		case StateNext, StatePrevious:
		default:
			return fmt.Errorf("key %q: unknown state %q", k.ID, k.State)
		}
	}
	if current != 1 {
		return fmt.Errorf("key set must have exactly one current key, has %d", current)
	}
	return nil
}

// Generate makes a new key. The kid is prefixed with the cluster name so that
// clusters sharing one JWKS never collide.
func Generate(cluster, alg string, state State, now time.Time) (Key, error) {
	if alg != string(jose.ES256) {
		return Key{}, fmt.Errorf("unsupported algorithm %q", alg)
	}
	if cluster == "" {
		return Key{}, errors.New("cluster name is required")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Key{}, err
	}
	now = now.UTC().Truncate(time.Second)
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return Key{}, err
	}
	kid := fmt.Sprintf("%s/%s-%x", cluster, now.Format("20060102T150405Z"), suffix)
	return Key{
		ID:             kid,
		State:          state,
		CreatedAt:      now,
		StateChangedAt: now,
		JWK:            jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: alg, Use: "sig"},
	}, nil
}
