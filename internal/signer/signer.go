// Package signer mints Workload Authorization Grants.
package signer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/arndt-s/wag-k8s/internal/keys"
	"github.com/arndt-s/wag-k8s/internal/wag"
)

// ErrNoKey means there is no current signing key yet.
var ErrNoKey = errors.New("no signing key")

// Claims are the inputs for one grant.
type Claims struct {
	Issuer   string
	Subject  string
	Audience string
	Scopes   []string
	Nickname string
	IssuedAt time.Time
	Expiry   time.Time
	// Extra claims, merged in last; they cannot override registered claims.
	Extra map[string]any
}

// Signed is a minted grant.
type Signed struct {
	Token string
	JTI   string
	KeyID string
}

// Signer signs with the current key of a key set.
type Signer struct {
	keys func() *keys.KeySet
}

func New(keys func() *keys.KeySet) *Signer {
	return &Signer{keys: keys}
}

// Ready reports whether a signing key is available.
func (s *Signer) Ready() bool { return s.keys().Current() != nil }

func (s *Signer) Sign(c Claims) (*Signed, error) {
	k := s.keys().Current()
	if k == nil {
		return nil, ErrNoKey
	}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(k.JWK.Algorithm), Key: k.JWK},
		(&jose.SignerOptions{}).WithType(wag.JWTType),
	)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	jti, err := newJTI()
	if err != nil {
		return nil, err
	}
	registered := jwt.Claims{
		Issuer:   c.Issuer,
		Subject:  c.Subject,
		IssuedAt: jwt.NewNumericDate(c.IssuedAt),
		Expiry:   jwt.NewNumericDate(c.Expiry),
		ID:       jti,
	}
	private := map[string]any{}
	for k, v := range c.Extra {
		private[k] = v
	}
	// aud is a single string, not an array (spec 5.1).
	private["aud"] = c.Audience
	if len(c.Scopes) > 0 {
		private["scope"] = strings.Join(c.Scopes, " ")
	}
	if c.Nickname != "" {
		private["nickname"] = c.Nickname
	}
	tok, err := jwt.Signed(sig).Claims(private).Claims(registered).Serialize()
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &Signed{Token: tok, JTI: jti, KeyID: k.ID}, nil
}

func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
