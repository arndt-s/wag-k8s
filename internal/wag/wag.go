// Package wag holds the core types and the seams (interfaces) of the issuer.
// It has no dependency on Kubernetes or any cloud SDK.
package wag

import (
	"context"
	"errors"
	"io"
	"time"
)

const (
	// GrantTypeTokenExchange is the RFC 8693 grant type.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	// TokenTypeJWT is the subject token type for a service account token.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
	// TokenTypeWAG is the token type of a Workload Authorization Grant.
	TokenTypeWAG = "urn:ietf:params:oauth:token-type:wag"
	// JWTType is the typ header of a Workload Authorization Grant.
	JWTType = "oauth-wag+jwt"
)

// Identity is the caller, as the Validator reports it.
type Identity struct {
	Namespace         string
	ServiceAccount    string
	ServiceAccountUID string

	// Bound-token extras; empty for tokens not bound to a pod.
	PodName  string
	PodUID   string
	NodeName string

	// Pod labels and annotations, filtered to the configured prefixes.
	PodLabels      map[string]string
	PodAnnotations map[string]string

	Extra map[string][]string

	// ExpiresAt is the expiry of the presented subject token. A grant never
	// outlives it.
	ExpiresAt time.Time
}

// ExchangeRequest is the part of a token exchange request that policy decides on.
type ExchangeRequest struct {
	Audience string
	Scopes   []string
}

// Grant is what policy allows for one request.
type Grant struct {
	Audience string
	Scopes   []string
}

// Validator turns a subject token into an Identity.
type Validator interface {
	Validate(ctx context.Context, token string) (*Identity, error)
}

// SubjectRenderer builds the sub and nickname claims for an Identity.
type SubjectRenderer interface {
	Render(id *Identity) (sub, nickname string, err error)
}

// Policy decides which audience and scopes an Identity may get.
type Policy interface {
	Authorize(ctx context.Context, id *Identity, req ExchangeRequest) (Grant, error)
}

// IssuerSource provides the iss value. Metadata and grants use the same source,
// so that they agree byte for byte.
type IssuerSource interface {
	Issuer(ctx context.Context) (string, error)
}

// Publisher stores public documents (issuer metadata, JWKS) where an
// authorization server can fetch them.
type Publisher interface {
	Get(ctx context.Context, path string) (body []byte, etag string, err error)
	// Put with ifMatch="" writes unconditionally; otherwise it fails with
	// ErrConflict when the object changed since etag was read.
	Put(ctx context.Context, path, contentType string, body io.Reader, ifMatch string) error
}

var (
	// ErrInvalidToken means the subject token was rejected.
	ErrInvalidToken = errors.New("invalid subject token")
	// ErrAudienceDenied means policy does not allow the requested audience.
	ErrAudienceDenied = errors.New("audience not allowed")
	// ErrScopeDenied means policy allows none of the requested scopes.
	ErrScopeDenied = errors.New("scope not allowed")
	// ErrConflict means a conditional write lost a race.
	ErrConflict = errors.New("conflict")
	// ErrNotFound means a stored object does not exist.
	ErrNotFound = errors.New("not found")
)
