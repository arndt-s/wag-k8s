package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defakto-security/wag-k8s/internal/wag"
)

const maxFormBytes = 64 << 10

// TokenHandler serves the RFC 8693 token endpoint.
type TokenHandler struct {
	Exchanger *Exchanger
}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := "error"
	defer func() { recordExchange(r.Context(), outcome, start) }()

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		outcome = "invalid_request"
		writeError(w, &Error{Code: "invalid_request", Description: "use POST", Status: http.StatusMethodNotAllowed})
		return
	}
	req, subjectToken, oerr := parseRequest(w, r)
	if oerr != nil {
		outcome = oerr.Code
		writeError(w, oerr)
		return
	}
	res, err := h.Exchanger.Exchange(r.Context(), subjectToken, req)
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Code: "server_error", Description: "internal error", Status: 500, Err: err}
		}
		outcome = e.Code
		level := slog.LevelInfo
		if e.Status >= 500 {
			level = slog.LevelError
		}
		slog.Log(r.Context(), level, "token exchange failed", "code", e.Code, "err", e.Err, "aud", req.Audience)
		writeError(w, e)
		return
	}
	outcome = "issued"
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:     res.Token,
		IssuedTokenType: wag.TokenTypeWAG,
		// The grant is not an access token for any resource (RFC 8693 2.2.1).
		TokenType: "N_A",
		ExpiresIn: int64(res.ExpiresIn / time.Second),
		Scope:     strings.Join(res.Scopes, " "),
	})
}

func parseRequest(w http.ResponseWriter, r *http.Request) (wag.ExchangeRequest, string, *Error) {
	bad := func(desc string) *Error { return &Error{Code: "invalid_request", Description: desc, Status: 400} }
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/x-www-form-urlencoded" {
		return wag.ExchangeRequest{}, "", bad("content type must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		return wag.ExchangeRequest{}, "", bad("malformed form body")
	}
	// Parameters only count in the body, never the query string.
	f := r.PostForm
	for k, vs := range f {
		if len(vs) > 1 {
			return wag.ExchangeRequest{}, "", bad("parameter " + k + " must not repeat")
		}
	}
	if gt := f.Get("grant_type"); gt != wag.GrantTypeTokenExchange {
		return wag.ExchangeRequest{}, "", &Error{Code: "unsupported_grant_type", Description: "grant_type must be " + wag.GrantTypeTokenExchange, Status: 400}
	}
	subjectToken := f.Get("subject_token")
	if subjectToken == "" {
		return wag.ExchangeRequest{}, "", bad("subject_token is required")
	}
	if f.Get("subject_token_type") != wag.TokenTypeJWT {
		return wag.ExchangeRequest{}, "", bad("subject_token_type must be " + wag.TokenTypeJWT)
	}
	if rt := f.Get("requested_token_type"); rt != "" && rt != wag.TokenTypeWAG {
		return wag.ExchangeRequest{}, "", bad("requested_token_type must be " + wag.TokenTypeWAG)
	}
	if f.Has("actor_token") || f.Has("actor_token_type") {
		return wag.ExchangeRequest{}, "", bad("delegation is not supported")
	}
	if f.Has("resource") {
		return wag.ExchangeRequest{}, "", &Error{Code: "invalid_target", Description: "resource is not supported; name the authorization server in audience", Status: 400}
	}
	aud := f.Get("audience")
	if aud == "" {
		return wag.ExchangeRequest{}, "", bad("audience is required: the issuer identifier of the target authorization server")
	}
	return wag.ExchangeRequest{Audience: aud, Scopes: strings.Fields(f.Get("scope"))}, subjectToken, nil
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeError(w http.ResponseWriter, e *Error) {
	writeJSON(w, e.Status, errorResponse{Error: e.Code, ErrorDescription: e.Description})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Documents serves issuer metadata and JWKS from memory. Swap replaces both
// at once.
type Documents struct {
	docs atomic.Pointer[docSet]
	// CacheControl is sent with every document.
	CacheControl string
}

type docSet struct {
	metaPath, jwksPath string
	meta, jwks         []byte
}

func (d *Documents) Swap(metaPath, jwksPath string, meta, jwks []byte) {
	d.docs.Store(&docSet{metaPath: metaPath, jwksPath: jwksPath, meta: meta, jwks: jwks})
}

func (d *Documents) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ds := d.docs.Load()
	if ds == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	var body []byte
	switch r.URL.Path {
	case ds.metaPath:
		body = ds.meta
	case ds.jwksPath:
		body = ds.jwks
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if d.CacheControl != "" {
		w.Header().Set("Cache-Control", d.CacheControl)
	}
	_, _ = w.Write(body)
}
