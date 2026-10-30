// Package server implements the token exchange endpoint and serves the issuer's
// public documents.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/arndt-s/wag-k8s/internal/signer"
	"github.com/arndt-s/wag-k8s/internal/validator"
	"github.com/arndt-s/wag-k8s/internal/wag"
)

// Exchanger turns a service account token into a grant:
// validate, authorize, render the subject, sign.
type Exchanger struct {
	Validator   wag.Validator
	Policy      wag.Policy
	Subjects    wag.SubjectRenderer
	Issuer      wag.IssuerSource
	Signer      *signer.Signer
	TTL         time.Duration
	ExtraClaims []string
	Audit       *slog.Logger
	Now         func() time.Time
}

// Result is a minted grant and what it was minted for.
type Result struct {
	Token     string
	Scopes    []string
	ExpiresIn time.Duration
}

// Exchange errors carry an OAuth error code.
type Error struct {
	Code        string
	Description string
	Status      int
	Err         error
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Description) }
func (e *Error) Unwrap() error { return e.Err }

func (x *Exchanger) Exchange(ctx context.Context, subjectToken string, req wag.ExchangeRequest) (*Result, error) {
	now := x.Now()

	id, err := x.Validator.Validate(ctx, subjectToken)
	switch {
	case errors.Is(err, validator.ErrUnavailable):
		return nil, &Error{Code: "temporarily_unavailable", Description: "could not validate subject_token", Status: 503, Err: err}
	case err != nil:
		// RFC 8693 2.2.2: an invalid subject_token is invalid_request.
		return nil, &Error{Code: "invalid_request", Description: "subject_token is invalid", Status: 400, Err: err}
	}

	grant, err := x.Policy.Authorize(ctx, id, req)
	switch {
	case errors.Is(err, wag.ErrAudienceDenied):
		return nil, &Error{Code: "invalid_target", Description: "audience is not allowed for this service account", Status: 400, Err: err}
	case errors.Is(err, wag.ErrScopeDenied):
		return nil, &Error{Code: "invalid_scope", Description: "requested scopes are not allowed for this service account", Status: 400, Err: err}
	case err != nil:
		return nil, &Error{Code: "server_error", Description: "policy error", Status: 500, Err: err}
	}

	sub, nickname, err := x.Subjects.Render(id)
	if err != nil {
		return nil, &Error{Code: "server_error", Description: "could not render subject", Status: 500, Err: err}
	}
	iss, err := x.Issuer.Issuer(ctx)
	if err != nil {
		return nil, &Error{Code: "temporarily_unavailable", Description: "issuer is not known", Status: 503, Err: err}
	}

	iat := now.Truncate(time.Second)
	exp := iat.Add(x.TTL)
	if !id.ExpiresAt.IsZero() && id.ExpiresAt.Before(exp) {
		exp = id.ExpiresAt
	}
	if !exp.After(iat) {
		return nil, &Error{Code: "invalid_request", Description: "subject_token expires too soon", Status: 400}
	}

	signed, err := x.Signer.Sign(signer.Claims{
		Issuer:   iss,
		Subject:  sub,
		Audience: grant.Audience,
		Scopes:   grant.Scopes,
		Nickname: nickname,
		IssuedAt: iat,
		Expiry:   exp,
		Extra:    kubernetesClaims(id, x.ExtraClaims),
	})
	if errors.Is(err, signer.ErrNoKey) {
		return nil, &Error{Code: "temporarily_unavailable", Description: "no signing key", Status: 503, Err: err}
	}
	if err != nil {
		return nil, &Error{Code: "server_error", Description: "could not sign", Status: 500, Err: err}
	}

	x.Audit.Info("grant issued",
		"sub", sub,
		"aud", grant.Audience,
		"scope", grant.Scopes,
		"jti", signed.JTI,
		"kid", signed.KeyID,
		"exp", exp.Unix(),
		"namespace", id.Namespace,
		"serviceAccount", id.ServiceAccount,
		"pod", id.PodName,
	)
	return &Result{Token: signed.Token, Scopes: grant.Scopes, ExpiresIn: exp.Sub(now)}, nil
}

// kubernetesClaims builds the opt-in "kubernetes.io" claim, shaped like the
// one in service account tokens.
func kubernetesClaims(id *wag.Identity, enabled []string) map[string]any {
	if len(enabled) == 0 {
		return nil
	}
	k := map[string]any{}
	for _, c := range enabled {
		switch c {
		case "namespace":
			k["namespace"] = id.Namespace
		case "serviceaccount":
			k["serviceaccount"] = map[string]string{"name": id.ServiceAccount, "uid": id.ServiceAccountUID}
		case "pod":
			if id.PodName != "" {
				k["pod"] = map[string]string{"name": id.PodName, "uid": id.PodUID}
			}
		case "node":
			if id.NodeName != "" {
				k["node"] = map[string]string{"name": id.NodeName}
			}
		}
	}
	return map[string]any{"kubernetes.io": k}
}
