package keys

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/defakto-security/wag-k8s/internal/wag"
)

func mustKey(t *testing.T, state State) Key {
	t.Helper()
	k, err := Generate("prod-eu1", "ES256", state, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestGenerateAndValidate(t *testing.T) {
	cur, next := mustKey(t, StateCurrent), mustKey(t, StateNext)
	if !strings.HasPrefix(cur.ID, "prod-eu1/") {
		t.Errorf("kid = %q", cur.ID)
	}
	ks := &KeySet{Keys: []Key{cur, next}}
	if err := ks.Validate(); err != nil {
		t.Fatal(err)
	}
	if ks.Current().ID != cur.ID {
		t.Error("wrong current key")
	}
	for _, k := range ks.PublicJWKS().Keys {
		if !k.IsPublic() {
			t.Error("JWKS leaks a private key")
		}
	}
	if err := (&KeySet{Keys: []Key{next}}).Validate(); err == nil {
		t.Error("expected error without a current key")
	}
	if err := (&KeySet{Keys: []Key{cur, cur}}).Validate(); err == nil {
		t.Error("expected error for duplicate kid")
	}
}

func TestEmptyJWKSIsAnArray(t *testing.T) {
	var ks *KeySet
	if ks.PublicJWKS().Keys == nil {
		t.Error("keys must marshal as [] not null")
	}
}

func TestSecretStoreRoundTripAndCAS(t *testing.T) {
	ctx := context.Background()
	s := NewSecretStore(fake.NewSimpleClientset(), "wag-system", "keys")

	if _, err := s.Load(ctx); !errors.Is(err, wag.ErrNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
	ks := &KeySet{Keys: []Key{mustKey(t, StateCurrent)}}
	if err := s.Save(ctx, ks, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, ks, ""); !errors.Is(err, wag.ErrConflict) {
		t.Fatalf("second create: err = %v, want conflict", err)
	}
	got, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("loaded key set is invalid: %v", err)
	}
	if got.Current().ID != ks.Current().ID {
		t.Error("round trip lost the current key")
	}
}

type memStore struct{ ks *KeySet }

func (m *memStore) Load(context.Context) (*KeySet, error) {
	if m.ks == nil {
		return nil, wag.ErrNotFound
	}
	return m.ks, nil
}
func (m *memStore) Save(context.Context, *KeySet, string) error { return nil }

func TestCacheIgnoresInvalidKeySets(t *testing.T) {
	c := NewCache(&memStore{}, time.Second)
	var changes int
	c.OnChange(func(*KeySet) { changes++ })

	good := &KeySet{Keys: []Key{mustKey(t, StateCurrent)}, Version: "1"}
	c.Set(good)
	c.Set(&KeySet{Version: "2"}) // no current key
	c.Set(good)                  // same version again
	if c.Get() != good || changes != 1 {
		t.Errorf("got %v after %d changes", c.Get(), changes)
	}
}

func TestSecretStoreWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := NewSecretStore(fake.NewSimpleClientset(), "wag-system", "keys")

	got := make(chan *KeySet, 4)
	go func() { _ = s.Watch(ctx, func(ks *KeySet) { got <- ks }) }()

	// The Secret does not exist yet; the bootstrap job creates it later.
	time.Sleep(100 * time.Millisecond)
	first := &KeySet{Keys: []Key{mustKey(t, StateCurrent)}}
	if err := s.Save(ctx, first, ""); err != nil {
		t.Fatal(err)
	}
	select {
	case ks := <-got:
		if ks.Current().ID != first.Current().ID {
			t.Errorf("watched kid = %q", ks.Current().ID)
		}
	case <-ctx.Done():
		t.Fatal("no key set from watch")
	}
}
