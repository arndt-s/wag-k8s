package config

import (
	"strings"
	"testing"
	"time"
)

const minimal = `
cluster: {name: prod-eu1}
issuer: {url: https://wag.example.com}
subject: {trustDomain: cluster.example.com}
keys: {secret: {namespace: wag-system}}
`

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.Template != DefaultSubjectTemplate {
		t.Errorf("template = %q", c.Subject.Template)
	}
	if c.Token.TTL.Duration != 5*time.Minute || c.Token.MaxTTL.Duration != 15*time.Minute {
		t.Errorf("ttl = %v / %v", c.Token.TTL, c.Token.MaxTTL)
	}
	if c.SAT.Audiences[0] != "wag-k8s" || c.Keys.Secret.Name != "wag-signing-keys" || c.Publish.Mode != ModeSingle {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestParseSharedDefaultIncludesCluster(t *testing.T) {
	c, err := Parse([]byte(minimal + "publish: {mode: shared}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.Template != DefaultSharedSubjectTemplate {
		t.Errorf("template = %q", c.Subject.Template)
	}
}

func TestParseErrors(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"unknown field":   {minimal + "bogus: 1\n", "unknown field"},
		"http issuer":     {strings.Replace(minimal, "https://", "http://", 1), "https URL"},
		"issuer query":    {strings.Replace(minimal, "url: https://wag.example.com", "url: 'https://wag.example.com?x=1'", 1), "query or fragment"},
		"issuer slash":    {strings.Replace(minimal, "example.com}", "example.com/}", 1), "must not end with"},
		"ttl over max":    {minimal + "token: {ttl: 1h}\n", "token.ttl"},
		"shared serve":    {minimal + "publish: {mode: shared, serve: true}\n", "publish.serve"},
		"shared no clust": {strings.Replace(minimal, "subject: {trustDomain: cluster.example.com}", "subject: {trustDomain: x, template: 'spiffe://x/{{ .Namespace }}'}", 1) + "publish: {mode: shared}\n", ".Cluster"},
		"extra claim":     {minimal + "token: {extraClaims: [secrets]}\n", "unknown claim"},
		"rule no aud":     {minimal + "policy: {rules: [{namespaces: [a]}]}\n", "audiences is required"},
		"bad duration":    {minimal + "token: {ttl: 5}\n", "duration"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
