package publish

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-jose/go-jose/v4"

	"github.com/defakto-security/wag-k8s/internal/keys"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

// fakeS3 speaks enough of the S3 REST API (path style) for GetObject and
// conditional PutObject.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	headers map[string]http.Header
	// beforePut runs before a PUT is applied, to simulate a racing writer.
	beforePut func(key string)
}

func newFakeS3(t *testing.T) (*fakeS3, *s3.Client) {
	f := &fakeS3{objects: map[string][]byte{}, headers: map[string]http.Header{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	client := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		UsePathStyle: true,
		Credentials:  aws.AnonymousCredentials{},
	})
	return f, client
}

func etagOf(b []byte) string {
	sum := md5.Sum(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func s3Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/")
	switch r.Method {
	case http.MethodGet:
		f.mu.Lock()
		b, ok := f.objects[key]
		f.mu.Unlock()
		if !ok {
			s3Error(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("ETag", etagOf(b))
		_, _ = w.Write(b)
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if f.beforePut != nil {
			f.beforePut(key)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		cur, exists := f.objects[key]
		if m := r.Header.Get("If-Match"); m != "" && (!exists || m != etagOf(cur)) {
			s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		if r.Header.Get("If-None-Match") == "*" && exists {
			s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		f.objects[key] = body
		f.headers[key] = r.Header.Clone()
		w.Header().Set("ETag", etagOf(body))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeS3) get(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objects[key]
}

func (f *fakeS3) set(key string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = b
}

func keySet(t *testing.T, cluster string) *keys.KeySet {
	t.Helper()
	k, err := keys.Generate(cluster, "ES256", keys.StateCurrent, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &keys.KeySet{Keys: []keys.Key{k}}
}

func kids(t *testing.T, b []byte) []string {
	t.Helper()
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range set.Keys {
		if !k.IsPublic() {
			t.Fatal("published a private key")
		}
		out = append(out, k.KeyID)
	}
	return out
}

func TestS3GetPutConditions(t *testing.T) {
	ctx := context.Background()
	_, client := newFakeS3(t)
	p := NewS3(client, "bucket", "issuers/a", "public, max-age=60")

	if _, _, err := p.Get(ctx, "/jwks.json"); !errors.Is(err, wag.ErrNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
	if err := p.Put(ctx, "/jwks.json", "application/json", strings.NewReader("1"), wag.Condition{IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if err := p.Put(ctx, "/jwks.json", "application/json", strings.NewReader("2"), wag.Condition{IfNoneMatch: true}); !errors.Is(err, wag.ErrConflict) {
		t.Fatalf("create over existing: err = %v", err)
	}
	b, etag, err := p.Get(ctx, "/jwks.json")
	if err != nil || string(b) != "1" || etag == "" {
		t.Fatalf("get: %q %q %v", b, etag, err)
	}
	if err := p.Put(ctx, "/jwks.json", "application/json", strings.NewReader("3"), wag.Condition{IfMatch: `"stale"`}); !errors.Is(err, wag.ErrConflict) {
		t.Fatalf("stale etag: err = %v", err)
	}
	if err := p.Put(ctx, "/jwks.json", "application/json", strings.NewReader("4"), wag.Condition{IfMatch: etag}); err != nil {
		t.Fatal(err)
	}
}

func TestSingleModeSync(t *testing.T) {
	ctx := context.Background()
	f, client := newFakeS3(t)
	target := NewS3(client, "bucket", "", "public, max-age=60")
	s := &Syncer{Issuer: "https://wag.example.com", Cluster: "prod-eu1"}
	ks := keySet(t, "prod-eu1")

	if err := s.Sync(ctx, ks, []Target{target}); err != nil {
		t.Fatal(err)
	}
	if got := kids(t, f.get("bucket/jwks.json")); len(got) != 1 || got[0] != ks.Current().ID {
		t.Errorf("jwks kids = %v", got)
	}
	var doc map[string]any
	if err := json.Unmarshal(f.get("bucket/.well-known/oauth-authorization-server"), &doc); err != nil || doc["issuer"] != "https://wag.example.com" {
		t.Errorf("metadata = %v %v", doc, err)
	}
	if cc := f.headers["bucket/jwks.json"].Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestSharedModeMergesClusters(t *testing.T) {
	ctx := context.Background()
	f, client := newFakeS3(t)
	target := NewS3(client, "bucket", "", "")
	eu, us := keySet(t, "prod-eu1"), keySet(t, "prod-us1")
	syncer := func(cluster string) *Syncer {
		return &Syncer{Issuer: "https://wag.example.com", Cluster: cluster, Shared: true}
	}

	if err := syncer("prod-eu1").Sync(ctx, eu, []Target{target}); err != nil {
		t.Fatal(err)
	}
	if err := syncer("prod-us1").Sync(ctx, us, []Target{target}); err != nil {
		t.Fatal(err)
	}
	if got := kids(t, f.get("bucket/jwks.json")); len(got) != 2 {
		t.Fatalf("kids = %v", got)
	}

	// eu rotates: its old key goes, us's key stays.
	eu2 := keySet(t, "prod-eu1")
	if err := syncer("prod-eu1").Sync(ctx, eu2, []Target{target}); err != nil {
		t.Fatal(err)
	}
	got := kids(t, f.get("bucket/jwks.json"))
	want := map[string]bool{eu2.Current().ID: true, us.Current().ID: true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("after rotation kids = %v, want %v", got, want)
	}
}

func TestSharedModeRetriesOnRace(t *testing.T) {
	ctx := context.Background()
	f, client := newFakeS3(t)
	target := NewS3(client, "bucket", "", "")
	eu, us := keySet(t, "prod-eu1"), keySet(t, "prod-us1")
	s := &Syncer{Issuer: "https://wag.example.com", Cluster: "prod-eu1", Shared: true}

	// Seed with us's key, then make us write again between eu's read and
	// eu's write, once.
	usJWKS, _ := json.Marshal(us.PublicJWKS())
	f.set("bucket/jwks.json", usJWKS)
	raced := false
	f.beforePut = func(key string) {
		if key == "bucket/jwks.json" && !raced {
			raced = true
			us2, _ := json.Marshal(jose.JSONWebKeySet{Keys: append(us.PublicJWKS().Keys, keySet(t, "prod-us1").PublicJWKS().Keys...)})
			f.set(key, us2)
		}
	}
	if err := s.Sync(ctx, eu, []Target{target}); err != nil {
		t.Fatal(err)
	}
	if got := kids(t, f.get("bucket/jwks.json")); len(got) != 3 {
		t.Fatalf("kids = %v, want eu + both us keys", got)
	}
}

func TestSharedModeRefusesUnreadableJWKS(t *testing.T) {
	f, client := newFakeS3(t)
	f.set("bucket/jwks.json", []byte("not json"))
	s := &Syncer{Issuer: "https://wag.example.com", Cluster: "prod-eu1", Shared: true}
	err := s.Sync(context.Background(), keySet(t, "prod-eu1"), []Target{NewS3(client, "bucket", "", "")})
	if err == nil || !strings.Contains(err.Error(), "not overwriting") {
		t.Fatalf("err = %v", err)
	}
	if string(f.get("bucket/jwks.json")) != "not json" {
		t.Error("overwrote unreadable JWKS")
	}
}

func TestSharedModeMetadataHasNoTokenEndpoint(t *testing.T) {
	f, client := newFakeS3(t)
	s := &Syncer{Issuer: "https://wag.example.com", TokenEndpoint: "http://wag.svc/token", Cluster: "a", Shared: true}
	if err := s.Sync(context.Background(), keySet(t, "a"), []Target{NewS3(client, "bucket", "", "")}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(f.get("bucket/.well-known/oauth-authorization-server"), &doc)
	if _, ok := doc["token_endpoint"]; ok || doc["issuer"] != "https://wag.example.com" {
		t.Errorf("metadata = %v", doc)
	}
}
