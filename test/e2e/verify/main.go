// Command verify checks a grant the way an authorization server would: it
// fetches the issuer's metadata and JWKS and verifies signature, typ and
// claims. It is used by the end-to-end test.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func main() {
	base := flag.String("base", "", "base URL the issuer's public listener is reachable at, e.g. http://localhost:18080")
	iss := flag.String("iss", "", "expected iss")
	aud := flag.String("aud", "", "expected aud")
	sub := flag.String("sub-prefix", "", "expected sub prefix")
	scope := flag.String("scope", "", "expected scope")
	label := flag.String("label", "", "a pod label key=value expected in kubernetes.io.pod.labels")
	absent := flag.String("absent-label", "", "a pod label key that must not be in the claims")
	flag.Parse()

	token, err := io.ReadAll(os.Stdin)
	check(err)
	if err := verify(strings.TrimSpace(string(token)), *base, *iss, *aud, *sub, *scope, *label, *absent); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("grant verified")
}

func verify(token, base, iss, aud, subPrefix, scope, label, absent string) error {
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := getJSON(base+"/.well-known/oauth-authorization-server", &meta); err != nil {
		return err
	}
	if meta.Issuer != iss {
		return fmt.Errorf("metadata issuer %q, want %q", meta.Issuer, iss)
	}
	// jwks_uri names the public host; fetch the same path from base.
	jwksPath := meta.JWKSURI[strings.Index(meta.JWKSURI[len("https://"):], "/")+len("https://"):]
	var jwks jose.JSONWebKeySet
	if err := getJSON(base+jwksPath, &jwks); err != nil {
		return err
	}

	tok, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return err
	}
	h := tok.Headers[0]
	if h.ExtraHeaders["typ"] != "oauth-wag+jwt" {
		return fmt.Errorf("typ %v", h.ExtraHeaders["typ"])
	}
	keys := jwks.Key(h.KeyID)
	if len(keys) == 0 {
		return fmt.Errorf("kid %q not in JWKS", h.KeyID)
	}
	var claims map[string]any
	var std jwt.Claims
	if err := tok.Claims(keys[0].Key, &claims, &std); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if err := std.ValidateWithLeeway(jwt.Expected{Issuer: iss, Time: time.Now()}, time.Minute); err != nil {
		return err
	}
	if claims["aud"] != aud {
		return fmt.Errorf("aud %v, want %q", claims["aud"], aud)
	}
	if s, _ := claims["sub"].(string); !strings.HasPrefix(s, subPrefix) {
		return fmt.Errorf("sub %q, want prefix %q", s, subPrefix)
	}
	if scope != "" && claims["scope"] != scope {
		return fmt.Errorf("scope %v, want %q", claims["scope"], scope)
	}
	k8s, _ := claims["kubernetes.io"].(map[string]any)
	pod, _ := k8s["pod"].(map[string]any)
	labels, _ := pod["labels"].(map[string]any)
	if k, v, ok := strings.Cut(label, "="); ok && labels[k] != v {
		return fmt.Errorf("pod label %s = %v, want %q", k, labels[k], v)
	}
	if _, ok := labels[absent]; absent != "" && ok {
		return fmt.Errorf("pod label %q should not be in the claims", absent)
	}
	return nil
}

func getJSON(url string, v any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
