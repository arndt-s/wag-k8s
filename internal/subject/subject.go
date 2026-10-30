// Package subject renders the sub and nickname claims from an Identity.
package subject

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"text/template"
	"unicode/utf8"

	"github.com/arndt-s/wag-k8s/internal/wag"
)

// MaxNicknameLength follows the spec's advice to keep nickname short.
const MaxNicknameLength = 64

// Data is what templates can refer to.
type Data struct {
	TrustDomain       string
	Cluster           string
	Namespace         string
	ServiceAccount    string
	ServiceAccountUID string
	PodName           string
	PodUID            string
	NodeName          string
}

// TemplateRenderer renders sub and nickname with text/template.
type TemplateRenderer struct {
	trustDomain string
	cluster     string
	sub         *template.Template
	nickname    *template.Template
}

func NewTemplateRenderer(trustDomain, cluster, subTemplate, nicknameTemplate string) (*TemplateRenderer, error) {
	sub, err := template.New("sub").Option("missingkey=error").Parse(subTemplate)
	if err != nil {
		return nil, fmt.Errorf("subject template: %w", err)
	}
	var nick *template.Template
	if nicknameTemplate != "" {
		nick, err = template.New("nickname").Option("missingkey=error").Parse(nicknameTemplate)
		if err != nil {
			return nil, fmt.Errorf("nickname template: %w", err)
		}
	}
	r := &TemplateRenderer{trustDomain: trustDomain, cluster: cluster, sub: sub, nickname: nick}
	// Fail at startup, not on the first request, if the template is unusable.
	if _, _, err := r.Render(&wag.Identity{
		Namespace: "ns", ServiceAccount: "sa", ServiceAccountUID: "uid",
		PodName: "pod", PodUID: "pod-uid", NodeName: "node",
	}); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *TemplateRenderer) Render(id *wag.Identity) (string, string, error) {
	d := Data{
		TrustDomain:       r.trustDomain,
		Cluster:           r.cluster,
		Namespace:         id.Namespace,
		ServiceAccount:    id.ServiceAccount,
		ServiceAccountUID: id.ServiceAccountUID,
		PodName:           id.PodName,
		PodUID:            id.PodUID,
		NodeName:          id.NodeName,
	}
	var buf bytes.Buffer
	if err := r.sub.Execute(&buf, d); err != nil {
		return "", "", fmt.Errorf("render sub: %w", err)
	}
	sub := buf.String()
	if err := validateSubject(sub); err != nil {
		return "", "", err
	}
	if r.nickname == nil {
		return sub, "", nil
	}
	buf.Reset()
	if err := r.nickname.Execute(&buf, d); err != nil {
		return "", "", fmt.Errorf("render nickname: %w", err)
	}
	return sub, truncate(buf.String(), MaxNicknameLength), nil
}

// validateSubject rejects empty subjects and, for SPIFFE IDs, the forms the
// SPIFFE ID spec forbids.
func validateSubject(sub string) error {
	if sub == "" {
		return errors.New("rendered sub is empty")
	}
	if !strings.HasPrefix(sub, "spiffe://") {
		return nil
	}
	u, err := url.Parse(sub)
	if err != nil {
		return fmt.Errorf("rendered sub is not a valid SPIFFE ID: %w", err)
	}
	if u.Host == "" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("rendered sub %q is not a valid SPIFFE ID", sub)
	}
	for _, seg := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("rendered sub %q has an empty or dot path segment", sub)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
