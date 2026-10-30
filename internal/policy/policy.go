// Package policy decides which audiences and scopes an identity may get.
// Everything is denied unless a rule allows it.
package policy

import (
	"context"
	"fmt"
	"slices"

	"github.com/defakto-security/wag-k8s/internal/config"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

const wildcard = "*"

// Rules is a Policy built from config rules.
type Rules struct {
	rules []config.Rule
}

func NewRules(rules []config.Rule) *Rules {
	return &Rules{rules: rules}
}

// Authorize grants the requested audience when at least one rule matching the
// identity lists it. Requested scopes are narrowed to the union of the scopes
// those rules allow; a request whose scopes are all refused is denied.
func (p *Rules) Authorize(_ context.Context, id *wag.Identity, req wag.ExchangeRequest) (wag.Grant, error) {
	audienceAllowed := false
	allowed := map[string]bool{}
	anyScope := false
	for _, r := range p.rules {
		if !matches(r.Namespaces, id.Namespace) {
			continue
		}
		if len(r.ServiceAccounts) > 0 && !matches(r.ServiceAccounts, id.ServiceAccount) {
			continue
		}
		if !matches(r.Audiences, req.Audience) {
			continue
		}
		audienceAllowed = true
		for _, s := range r.Scopes {
			if s == wildcard {
				anyScope = true
			}
			allowed[s] = true
		}
	}
	if !audienceAllowed {
		return wag.Grant{}, fmt.Errorf("%w: %s/%s may not get a grant for %q", wag.ErrAudienceDenied, id.Namespace, id.ServiceAccount, req.Audience)
	}
	g := wag.Grant{Audience: req.Audience}
	for _, s := range req.Scopes {
		if anyScope || allowed[s] {
			g.Scopes = append(g.Scopes, s)
		}
	}
	if len(req.Scopes) > 0 && len(g.Scopes) == 0 {
		return wag.Grant{}, fmt.Errorf("%w: none of the requested scopes are allowed for %q", wag.ErrScopeDenied, req.Audience)
	}
	return g, nil
}

func matches(patterns []string, v string) bool {
	return slices.Contains(patterns, wildcard) || slices.Contains(patterns, v)
}
