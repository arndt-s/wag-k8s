package subject

import (
	"strings"
	"testing"

	"github.com/defakto-security/wag-k8s/internal/config"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

func TestRenderDefault(t *testing.T) {
	r, err := NewTemplateRenderer("cluster.example.com", "prod-eu1", config.DefaultSubjectTemplate, config.DefaultNicknameTemplate)
	if err != nil {
		t.Fatal(err)
	}
	sub, nick, err := r.Render(&wag.Identity{Namespace: "team-a", ServiceAccount: "bot", ServiceAccountUID: "1234"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "spiffe://cluster.example.com/ns/team-a/sa/bot/1234"; sub != want {
		t.Errorf("sub = %q, want %q", sub, want)
	}
	if nick != "team-a/bot" {
		t.Errorf("nickname = %q", nick)
	}
}

func TestRenderShared(t *testing.T) {
	r, err := NewTemplateRenderer("td", "prod-eu1", config.DefaultSharedSubjectTemplate, "")
	if err != nil {
		t.Fatal(err)
	}
	sub, nick, err := r.Render(&wag.Identity{Namespace: "n", ServiceAccount: "s", ServiceAccountUID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "spiffe://td/cluster/prod-eu1/ns/n/sa/s/u"; sub != want || nick != "" {
		t.Errorf("sub = %q nick = %q", sub, nick)
	}
}

func TestRenderRejectsBadSPIFFEID(t *testing.T) {
	r, err := NewTemplateRenderer("td", "c", "spiffe://td/ns/{{ .Namespace }}/pod/{{ .PodName }}", "")
	if err != nil {
		t.Fatal(err)
	}
	// No pod name: empty path segment.
	if _, _, err := r.Render(&wag.Identity{Namespace: "n", ServiceAccount: "s"}); err == nil {
		t.Error("expected error for empty segment")
	}
}

func TestBadTemplateFailsEarly(t *testing.T) {
	if _, err := NewTemplateRenderer("td", "c", "{{ .Nope }}", ""); err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestNicknameTruncated(t *testing.T) {
	r, err := NewTemplateRenderer("td", "c", "x", strings.Repeat("ä", 100))
	if err != nil {
		t.Fatal(err)
	}
	_, nick, err := r.Render(&wag.Identity{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(nick)); n != MaxNicknameLength {
		t.Errorf("nickname has %d runes", n)
	}
}
