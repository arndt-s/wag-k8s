// Package config loads and validates the issuer configuration file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// Duration is a time.Duration that reads from strings such as "5m".
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"5m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

type Config struct {
	Cluster Cluster `json:"cluster"`
	Issuer  Issuer  `json:"issuer"`
	SAT     SAT     `json:"sat"`
	Subject Subject `json:"subject"`
	Token   Token   `json:"token"`
	Keys    Keys    `json:"keys"`
	Publish Publish `json:"publish"`
	Policy  Policy  `json:"policy"`
	Server  Server  `json:"server"`
}

type Cluster struct {
	// Name is unique and immutable; it prefixes key IDs and, in shared mode,
	// appears in sub.
	Name string `json:"name"`
}

type Issuer struct {
	URL string `json:"url"`
	// TokenEndpoint is advertised in metadata when set. It is usually a
	// cluster-internal URL.
	TokenEndpoint string `json:"tokenEndpoint,omitempty"`
}

type SAT struct {
	// Audiences a service account token must be minted for.
	Audiences []string `json:"audiences"`
	// CacheTTL bounds how long a TokenReview result is reused.
	CacheTTL Duration `json:"cacheTTL"`
}

type Subject struct {
	Template         string `json:"template"`
	TrustDomain      string `json:"trustDomain"`
	NicknameTemplate string `json:"nicknameTemplate"`
}

type Token struct {
	TTL    Duration `json:"ttl"`
	MaxTTL Duration `json:"maxTTL"`
	// ExtraClaims opts in to Kubernetes claims under "kubernetes.io":
	// namespace, serviceaccount, pod, node.
	ExtraClaims []string `json:"extraClaims,omitempty"`
}

type Keys struct {
	Store       string    `json:"store"`
	Secret      SecretRef `json:"secret"`
	Algorithm   string    `json:"algorithm"`
	RotateEvery Duration  `json:"rotateEvery"`
	Overlap     Duration  `json:"overlap"`
}

type SecretRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type Publish struct {
	Mode  string `json:"mode"`
	Serve bool   `json:"serve"`
}

type Policy struct {
	Rules []Rule `json:"rules"`
}

// Rule allows identities matching Namespaces and ServiceAccounts to get grants
// for Audiences with Scopes. "*" matches anything.
type Rule struct {
	Namespaces      []string `json:"namespaces"`
	ServiceAccounts []string `json:"serviceAccounts,omitempty"`
	Audiences       []string `json:"audiences"`
	Scopes          []string `json:"scopes,omitempty"`
}

type Server struct {
	// PublicAddr serves issuer metadata and JWKS.
	PublicAddr string `json:"publicAddr"`
	// TokenAddr serves the token endpoint; keep it cluster-internal.
	TokenAddr string `json:"tokenAddr"`
	// AdminAddr serves health checks and metrics.
	AdminAddr string `json:"adminAddr"`
	TokenTLS  TLS    `json:"tokenTLS,omitempty"`
}

type TLS struct {
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
}

const (
	ModeSingle = "single"
	ModeShared = "shared"

	DefaultSubjectTemplate       = "spiffe://{{ .TrustDomain }}/ns/{{ .Namespace }}/sa/{{ .ServiceAccount }}/{{ .ServiceAccountUID }}"
	DefaultSharedSubjectTemplate = "spiffe://{{ .TrustDomain }}/cluster/{{ .Cluster }}/ns/{{ .Namespace }}/sa/{{ .ServiceAccount }}/{{ .ServiceAccountUID }}"
	DefaultNicknameTemplate      = "{{ .Namespace }}/{{ .ServiceAccount }}"
)

// Load reads a YAML config file, applies defaults and validates it.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse reads a YAML config, applies defaults and validates it.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.SetDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) SetDefaults() {
	if len(c.SAT.Audiences) == 0 {
		c.SAT.Audiences = []string{"wag-k8s"}
	}
	if c.SAT.CacheTTL.Duration == 0 {
		c.SAT.CacheTTL.Duration = time.Minute
	}
	if c.Publish.Mode == "" {
		c.Publish.Mode = ModeSingle
	}
	if c.Subject.Template == "" {
		if c.Publish.Mode == ModeShared {
			c.Subject.Template = DefaultSharedSubjectTemplate
		} else {
			c.Subject.Template = DefaultSubjectTemplate
		}
	}
	if c.Subject.NicknameTemplate == "" {
		c.Subject.NicknameTemplate = DefaultNicknameTemplate
	}
	if c.Token.TTL.Duration == 0 {
		c.Token.TTL.Duration = 5 * time.Minute
	}
	if c.Token.MaxTTL.Duration == 0 {
		c.Token.MaxTTL.Duration = 15 * time.Minute
	}
	if c.Keys.Store == "" {
		c.Keys.Store = "secret"
	}
	if c.Keys.Secret.Name == "" {
		c.Keys.Secret.Name = "wag-signing-keys"
	}
	if c.Keys.Algorithm == "" {
		c.Keys.Algorithm = "ES256"
	}
	if c.Keys.RotateEvery.Duration == 0 {
		c.Keys.RotateEvery.Duration = 30 * 24 * time.Hour
	}
	if c.Keys.Overlap.Duration == 0 {
		c.Keys.Overlap.Duration = 24 * time.Hour
	}
	if c.Server.PublicAddr == "" {
		c.Server.PublicAddr = ":8080"
	}
	if c.Server.TokenAddr == "" {
		c.Server.TokenAddr = ":8443"
	}
	if c.Server.AdminAddr == "" {
		c.Server.AdminAddr = ":9090"
	}
}

var validExtraClaims = map[string]bool{"namespace": true, "serviceaccount": true, "pod": true, "node": true}

func (c *Config) Validate() error {
	var errs []error
	if c.Cluster.Name == "" {
		errs = append(errs, errors.New("cluster.name is required"))
	} else if strings.ContainsAny(c.Cluster.Name, "/ ") {
		errs = append(errs, errors.New("cluster.name must not contain '/' or spaces"))
	}
	if err := ValidateIssuerURL(c.Issuer.URL); err != nil {
		errs = append(errs, err)
	}
	if c.Subject.TrustDomain == "" {
		errs = append(errs, errors.New("subject.trustDomain is required"))
	}
	if c.Publish.Mode != ModeSingle && c.Publish.Mode != ModeShared {
		errs = append(errs, fmt.Errorf("publish.mode must be %q or %q", ModeSingle, ModeShared))
	}
	if c.Publish.Mode == ModeShared && c.Publish.Serve {
		errs = append(errs, errors.New("publish.serve is not supported in shared mode; publish to an external sink"))
	}
	if c.Publish.Mode == ModeShared && !strings.Contains(c.Subject.Template, ".Cluster") {
		errs = append(errs, errors.New("subject.template must include {{ .Cluster }} in shared mode"))
	}
	if c.Token.TTL.Duration <= 0 || c.Token.TTL.Duration > c.Token.MaxTTL.Duration {
		errs = append(errs, errors.New("token.ttl must be positive and at most token.maxTTL"))
	}
	for _, ec := range c.Token.ExtraClaims {
		if !validExtraClaims[ec] {
			errs = append(errs, fmt.Errorf("token.extraClaims: unknown claim %q", ec))
		}
	}
	if c.Keys.Store != "secret" {
		errs = append(errs, fmt.Errorf("keys.store %q is not supported", c.Keys.Store))
	}
	if c.Keys.Secret.Namespace == "" {
		errs = append(errs, errors.New("keys.secret.namespace is required"))
	}
	if c.Keys.Algorithm != "ES256" {
		errs = append(errs, fmt.Errorf("keys.algorithm %q is not supported", c.Keys.Algorithm))
	}
	if c.Keys.Overlap.Duration < c.Token.MaxTTL.Duration {
		errs = append(errs, errors.New("keys.overlap must be at least token.maxTTL"))
	}
	for i, r := range c.Policy.Rules {
		if len(r.Namespaces) == 0 {
			errs = append(errs, fmt.Errorf("policy.rules[%d].namespaces is required", i))
		}
		if len(r.Audiences) == 0 {
			errs = append(errs, fmt.Errorf("policy.rules[%d].audiences is required", i))
		}
	}
	if (c.Server.TokenTLS.CertFile == "") != (c.Server.TokenTLS.KeyFile == "") {
		errs = append(errs, errors.New("server.tokenTLS needs both certFile and keyFile"))
	}
	return errors.Join(errs...)
}

// ValidateIssuerURL checks the rules for iss: https, no query, no fragment.
func ValidateIssuerURL(s string) error {
	if s == "" {
		return errors.New("issuer.url is required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("issuer.url: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("issuer.url must be an https URL")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("issuer.url must not have a query or fragment")
	}
	if strings.HasSuffix(u.Path, "/") {
		return errors.New("issuer.url must not end with '/'")
	}
	return nil
}
