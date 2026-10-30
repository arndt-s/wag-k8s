package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/arndt-s/wag-k8s/internal/config"
	"github.com/arndt-s/wag-k8s/internal/issuer"
	"github.com/arndt-s/wag-k8s/internal/keys"
	"github.com/arndt-s/wag-k8s/internal/metadata"
	"github.com/arndt-s/wag-k8s/internal/policy"
	"github.com/arndt-s/wag-k8s/internal/signer"
	"github.com/arndt-s/wag-k8s/internal/subject"
	"github.com/arndt-s/wag-k8s/internal/validator"
	"github.com/arndt-s/wag-k8s/internal/wag"
)

const (
	iss = "https://wag.example.com"
	as  = "https://as.saas.example"
)

var now = time.Unix(1_800_000_000, 0)

type fakeValidator struct {
	id  *wag.Identity
	err error
}

func (f fakeValidator) Validate(context.Context, string) (*wag.Identity, error) { return f.id, f.err }

func setup(t *testing.T, v wag.Validator, extra []string) (*TokenHandler, *keys.KeySet) {
	t.Helper()
	k, err := keys.Generate("prod-eu1", "ES256", keys.StateCurrent, now)
	if err != nil {
		t.Fatal(err)
	}
	ks := &keys.KeySet{Keys: []keys.Key{k}}
	r, err := subject.NewTemplateRenderer("cluster.example.com", "prod-eu1", config.DefaultSubjectTemplate, config.DefaultNicknameTemplate)
	if err != nil {
		t.Fatal(err)
	}
	src, _ := issuer.NewStatic(iss)
	return &TokenHandler{Exchanger: &Exchanger{
		Validator: v,
		Policy: policy.NewRules([]config.Rule{
			{Namespaces: []string{"team-a"}, Audiences: []string{as}, Scopes: []string{"issues:read"}},
		}),
		Subjects:    r,
		Issuer:      src,
		Signer:      signer.New(func() *keys.KeySet { return ks }),
		TTL:         5 * time.Minute,
		ExtraClaims: extra,
		Audit:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:         func() time.Time { return now },
	}}, ks
}

func identity(exp time.Time) *wag.Identity {
	return &wag.Identity{Namespace: "team-a", ServiceAccount: "bot", ServiceAccountUID: "uid-1", PodName: "bot-1", PodUID: "p1", ExpiresAt: exp}
}

func form(overrides map[string]string) url.Values {
	f := url.Values{
		"grant_type":           {wag.GrantTypeTokenExchange},
		"subject_token":        {"sat"},
		"subject_token_type":   {wag.TokenTypeJWT},
		"requested_token_type": {wag.TokenTypeWAG},
		"audience":             {as},
		"scope":                {"issues:read issues:write"},
	}
	for k, v := range overrides {
		if v == "" {
			f.Del(k)
		} else {
			f.Set(k, v)
		}
	}
	return f
}

func post(h http.Handler, f url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestExchangeIssuesValidGrant(t *testing.T) {
	h, ks := setup(t, fakeValidator{id: identity(now.Add(time.Hour))}, []string{"namespace", "pod"})
	rec := post(h, form(nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing Cache-Control: no-store")
	}
	var resp tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.IssuedTokenType != wag.TokenTypeWAG || resp.TokenType != "N_A" || resp.ExpiresIn != 300 || resp.Scope != "issues:read" {
		t.Errorf("response = %+v", resp)
	}

	tok, err := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	hdr := tok.Headers[0]
	if hdr.ExtraHeaders["typ"] != wag.JWTType || hdr.KeyID != ks.Current().ID {
		t.Errorf("header = %+v", hdr)
	}
	// Verify against the published JWKS, as an authorization server would.
	_, jwksBody, err := metadata.Render(iss, "", ks)
	if err != nil {
		t.Fatal(err)
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBody, &jwks); err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := tok.Claims(jwks.Key(hdr.KeyID)[0].Key, &claims); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"iss":      iss,
		"sub":      "spiffe://cluster.example.com/ns/team-a/sa/bot/uid-1",
		"aud":      as, // a string, not an array
		"scope":    "issues:read",
		"nickname": "team-a/bot",
		"iat":      float64(now.Unix()),
		"exp":      float64(now.Add(5 * time.Minute).Unix()),
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("%s = %#v, want %#v", k, claims[k], v)
		}
	}
	if s, _ := claims["jti"].(string); len(s) < 16 {
		t.Errorf("jti = %v", claims["jti"])
	}
	k8s, _ := claims["kubernetes.io"].(map[string]any)
	if k8s["namespace"] != "team-a" || k8s["pod"] == nil || k8s["serviceaccount"] != nil {
		t.Errorf("kubernetes.io = %v", k8s)
	}
}

func TestExpiryCappedAtSAT(t *testing.T) {
	h, _ := setup(t, fakeValidator{id: identity(now.Add(90 * time.Second))}, nil)
	rec := post(h, form(nil))
	var resp tokenResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ExpiresIn != 90 {
		t.Errorf("expires_in = %d, want 90", resp.ExpiresIn)
	}
}

func TestNoExtraClaimsByDefault(t *testing.T) {
	h, _ := setup(t, fakeValidator{id: identity(now.Add(time.Hour))}, nil)
	var resp tokenResponse
	_ = json.Unmarshal(post(h, form(nil)).Body.Bytes(), &resp)
	tok, _ := jwt.ParseSigned(resp.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	var claims map[string]any
	_ = tok.UnsafeClaimsWithoutVerification(&claims)
	if _, ok := claims["kubernetes.io"]; ok {
		t.Error("kubernetes.io claim present without opt-in")
	}
}

func TestExchangeErrors(t *testing.T) {
	ok := fakeValidator{id: identity(now.Add(time.Hour))}
	for name, tc := range map[string]struct {
		v      wag.Validator
		form   url.Values
		status int
		code   string
	}{
		"wrong grant type":     {ok, form(map[string]string{"grant_type": "client_credentials"}), 400, "unsupported_grant_type"},
		"missing token":        {ok, form(map[string]string{"subject_token": ""}), 400, "invalid_request"},
		"wrong token type":     {ok, form(map[string]string{"subject_token_type": "urn:ietf:params:oauth:token-type:access_token"}), 400, "invalid_request"},
		"wrong requested":      {ok, form(map[string]string{"requested_token_type": wag.TokenTypeJWT}), 400, "invalid_request"},
		"missing audience":     {ok, form(map[string]string{"audience": ""}), 400, "invalid_request"},
		"actor token":          {ok, form(map[string]string{"actor_token": "x"}), 400, "invalid_request"},
		"resource":             {ok, form(map[string]string{"resource": "https://rs"}), 400, "invalid_target"},
		"audience not allowed": {ok, form(map[string]string{"audience": "https://evil"}), 400, "invalid_target"},
		"scope not allowed":    {ok, form(map[string]string{"scope": "admin"}), 400, "invalid_scope"},
		"bad token":            {fakeValidator{err: wag.ErrInvalidToken}, form(nil), 400, "invalid_request"},
		"api down":             {fakeValidator{err: validator.ErrUnavailable}, form(nil), 503, "temporarily_unavailable"},
		"repeated audience": {ok, func() url.Values {
			f := form(nil)
			f.Add("audience", "https://as.other")
			return f
		}(), 400, "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := setup(t, tc.v, nil)
			rec := post(h, tc.form)
			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}
			var e errorResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &e)
			if e.Error != tc.code {
				t.Errorf("error = %q, want %q (%s)", e.Error, tc.code, e.ErrorDescription)
			}
		})
	}
}

func TestNoSigningKey(t *testing.T) {
	h, _ := setup(t, fakeValidator{id: identity(now.Add(time.Hour))}, nil)
	h.Exchanger.Signer = signer.New(func() *keys.KeySet { return nil })
	rec := post(h, form(nil))
	if rec.Code != 503 {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestRejectsGetAndQueryParams(t *testing.T) {
	h, _ := setup(t, fakeValidator{id: identity(now.Add(time.Hour))}, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/token?"+form(nil).Encode(), nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d", rec.Code)
	}
	// Token in the query string is not read.
	req := httptest.NewRequest(http.MethodPost, "/token?subject_token=sat", strings.NewReader(form(map[string]string{"subject_token": ""}).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Errorf("query token status = %d", rec.Code)
	}
}

func TestDocuments(t *testing.T) {
	k, _ := keys.Generate("c", "ES256", keys.StateCurrent, now)
	ks := &keys.KeySet{Keys: []keys.Key{k}}
	issuerURL := "https://wag.example.com/tenant-a"
	p, err := metadata.PathsFor(issuerURL)
	if err != nil {
		t.Fatal(err)
	}
	if p.Metadata != "/.well-known/oauth-authorization-server/tenant-a" || p.JWKS != "/tenant-a/jwks.json" {
		t.Fatalf("paths = %+v", p)
	}
	meta, jwks, err := metadata.Render(issuerURL, "", ks)
	if err != nil {
		t.Fatal(err)
	}
	d := &Documents{CacheControl: "public, max-age=300"}
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	if get(p.Metadata).Code != 503 {
		t.Error("expected 503 before documents are loaded")
	}
	d.Swap(p.Metadata, p.JWKS, meta, jwks)

	var doc metadata.Document
	if err := json.Unmarshal(get(p.Metadata).Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Issuer != issuerURL || doc.JWKSURI != "https://wag.example.com/tenant-a/jwks.json" {
		t.Errorf("doc = %+v", doc)
	}
	if rec := get(p.JWKS); rec.Code != 200 || rec.Header().Get("Cache-Control") == "" {
		t.Errorf("jwks: %d %v", rec.Code, rec.Header())
	}
	if get("/other").Code != 404 {
		t.Error("expected 404")
	}
}

