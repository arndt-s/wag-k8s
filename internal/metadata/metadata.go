// Package metadata renders the public documents an authorization server
// fetches to trust the issuer: RFC 8414 metadata and the JWKS.
package metadata

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/defakto-security/wag-k8s/internal/keys"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

const (
	wellKnownPrefix = "/.well-known/oauth-authorization-server"
	jwksName        = "/jwks.json"
)

// Paths are where the documents live, relative to the issuer's host.
type Paths struct {
	Metadata string
	JWKS     string
}

// PathsFor follows RFC 8414 section 3.1: the well-known segment goes between
// host and the issuer's path.
func PathsFor(issuer string) (Paths, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return Paths{}, err
	}
	return Paths{
		Metadata: wellKnownPrefix + u.Path,
		JWKS:     u.Path + jwksName,
	}, nil
}

// Document is the issuer metadata.
type Document struct {
	Issuer                            string   `json:"issuer"`
	JWKSURI                           string   `json:"jwks_uri"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// Render returns the metadata and JWKS bodies.
func Render(issuer, tokenEndpoint string, ks *keys.KeySet) (meta, jwks []byte, err error) {
	p, err := PathsFor(issuer)
	if err != nil {
		return nil, nil, err
	}
	u, _ := url.Parse(issuer)
	doc := Document{
		// Byte-for-byte the same value as iss (spec 6.1).
		Issuer:                            issuer,
		JWKSURI:                           fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, p.JWKS),
		TokenEndpoint:                     tokenEndpoint,
		GrantTypesSupported:               []string{wag.GrantTypeTokenExchange},
		TokenEndpointAuthMethodsSupported: []string{"none"},
	}
	if meta, err = json.Marshal(doc); err != nil {
		return nil, nil, err
	}
	if jwks, err = json.Marshal(ks.PublicJWKS()); err != nil {
		return nil, nil, err
	}
	return meta, jwks, nil
}
