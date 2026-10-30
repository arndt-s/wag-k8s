package policy

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/defakto-security/wag-k8s/internal/config"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

func TestAuthorize(t *testing.T) {
	p := NewRules([]config.Rule{
		{Namespaces: []string{"team-a"}, Audiences: []string{"https://as.one"}, Scopes: []string{"read"}},
		{Namespaces: []string{"team-a"}, ServiceAccounts: []string{"writer"}, Audiences: []string{"https://as.one"}, Scopes: []string{"write"}},
		{Namespaces: []string{"*"}, Audiences: []string{"https://as.open"}, Scopes: []string{"*"}},
	})
	id := func(ns, sa string) *wag.Identity { return &wag.Identity{Namespace: ns, ServiceAccount: sa} }

	for name, tc := range map[string]struct {
		id         *wag.Identity
		req        wag.ExchangeRequest
		wantErr    error
		wantScopes []string
	}{
		"no rule for namespace": {id("team-b", "x"), wag.ExchangeRequest{Audience: "https://as.one"}, wag.ErrAudienceDenied, nil},
		"unknown audience":      {id("team-a", "x"), wag.ExchangeRequest{Audience: "https://as.other"}, wag.ErrAudienceDenied, nil},
		"no scopes requested":   {id("team-a", "x"), wag.ExchangeRequest{Audience: "https://as.one"}, nil, nil},
		"allowed scope":         {id("team-a", "x"), wag.ExchangeRequest{Audience: "https://as.one", Scopes: []string{"read"}}, nil, []string{"read"}},
		"narrowed":              {id("team-a", "x"), wag.ExchangeRequest{Audience: "https://as.one", Scopes: []string{"read", "write"}}, nil, []string{"read"}},
		"union across rules":    {id("team-a", "writer"), wag.ExchangeRequest{Audience: "https://as.one", Scopes: []string{"read", "write"}}, nil, []string{"read", "write"}},
		"all scopes refused":    {id("team-a", "x"), wag.ExchangeRequest{Audience: "https://as.one", Scopes: []string{"admin"}}, wag.ErrScopeDenied, nil},
		"wildcard ns and scope": {id("any", "x"), wag.ExchangeRequest{Audience: "https://as.open", Scopes: []string{"z"}}, nil, []string{"z"}},
	} {
		t.Run(name, func(t *testing.T) {
			g, err := p.Authorize(context.Background(), tc.id, tc.req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && !slices.Equal(g.Scopes, tc.wantScopes) {
				t.Errorf("scopes = %v, want %v", g.Scopes, tc.wantScopes)
			}
		})
	}
}

func TestDenyByDefault(t *testing.T) {
	_, err := NewRules(nil).Authorize(context.Background(), &wag.Identity{Namespace: "a"}, wag.ExchangeRequest{Audience: "x"})
	if !errors.Is(err, wag.ErrAudienceDenied) {
		t.Fatalf("err = %v", err)
	}
}
