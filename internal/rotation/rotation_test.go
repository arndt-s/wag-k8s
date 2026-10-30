package rotation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defakto-security/wag-k8s/internal/keys"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

var policy = Policy{
	Cluster:     "prod-eu1",
	Algorithm:   "ES256",
	RotateEvery: 30 * 24 * time.Hour,
	Overlap:     24 * time.Hour,
	MaxTTL:      15 * time.Minute,
}

func states(ks *keys.KeySet) map[keys.State]int {
	m := map[keys.State]int{}
	for _, k := range ks.Keys {
		m[k.State]++
	}
	return m
}

func TestLifecycle(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	step := func(ks *keys.KeySet, at time.Time) (*keys.KeySet, []Change) {
		t.Helper()
		out, ch, err := Plan(ks, policy, at)
		if err != nil {
			t.Fatal(err)
		}
		// Idempotent: planning again at the same time changes nothing.
		if _, again, err := Plan(out, policy, at); err != nil || len(again) != 0 {
			t.Fatalf("second plan at %v: %v %v", at, again, err)
		}
		return out, ch
	}

	ks, ch := step(&keys.KeySet{}, t0)
	if len(ch) != 1 || ch[0].Action != "created" || states(ks)[keys.StateCurrent] != 1 {
		t.Fatalf("bootstrap: %v", ch)
	}
	first := ks.Current().ID

	// Nothing to do mid-life.
	if _, ch = step(ks, t0.Add(10*24*time.Hour)); len(ch) != 0 {
		t.Fatalf("mid-life: %v", ch)
	}

	// One overlap before rotation is due, a next key is published.
	ks, ch = step(ks, t0.Add(29*24*time.Hour))
	if len(ch) != 1 || ch[0].Action != "added-next" || ks.Current().ID != first {
		t.Fatalf("add next: %v", ch)
	}

	// After the overlap, next becomes current and the old key previous.
	ks, ch = step(ks, t0.Add(30*24*time.Hour))
	if len(ch) != 1 || ch[0].Action != "promoted" || ks.Current().ID == first {
		t.Fatalf("promote: %v", ch)
	}
	if s := states(ks); s[keys.StatePrevious] != 1 || s[keys.StateNext] != 0 {
		t.Fatalf("after promote: %v", s)
	}

	// Previous stays published for overlap + maxTTL, then goes.
	if _, ch = step(ks, t0.Add(31*24*time.Hour)); len(ch) != 0 {
		t.Fatalf("too early to remove: %v", ch)
	}
	ks, ch = step(ks, t0.Add(31*24*time.Hour+policy.MaxTTL))
	if len(ch) != 1 || ch[0].Action != "removed" || ch[0].KeyID != first || len(ks.Keys) != 1 {
		t.Fatalf("remove: %v", ch)
	}
}

func TestLateRunCatchesUp(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ks, _, _ := Plan(&keys.KeySet{}, policy, t0)
	// The job didn't run for a long time: it adds a next key, but must not
	// promote it in the same run, since nobody has seen it published yet.
	ks, ch, err := Plan(ks, policy, t0.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) != 1 || ch[0].Action != "added-next" {
		t.Fatalf("changes = %v", ch)
	}
}

func TestPlanDoesNotMutateInput(t *testing.T) {
	t0 := time.Now()
	ks, _, _ := Plan(&keys.KeySet{}, policy, t0)
	before := ks.Keys[0].State
	_, _, _ = Plan(ks, Policy{Cluster: "c", Algorithm: "ES256", RotateEvery: time.Hour, Overlap: time.Hour}, t0.Add(2*time.Hour))
	if ks.Keys[0].State != before || len(ks.Keys) != 1 {
		t.Error("Plan mutated its input")
	}
}

type memStore struct {
	ks        *keys.KeySet
	version   int
	conflicts int
}

func (m *memStore) Load(context.Context) (*keys.KeySet, error) {
	if m.ks == nil {
		return nil, wag.ErrNotFound
	}
	c := *m.ks
	c.Version = string(rune('0' + m.version))
	return &c, nil
}

func (m *memStore) Save(_ context.Context, ks *keys.KeySet, version string) error {
	if m.conflicts > 0 {
		m.conflicts--
		return wag.ErrConflict
	}
	want := ""
	if m.ks != nil {
		want = string(rune('0' + m.version))
	}
	if version != want {
		return wag.ErrConflict
	}
	m.ks = ks
	m.version++
	return nil
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	now := func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
	s := &memStore{conflicts: 2}

	ks, changed, err := Run(ctx, s, policy, now, true)
	if err != nil || !changed || ks.Current() == nil {
		t.Fatalf("init: %v %v", changed, err)
	}
	// initOnly leaves an existing key set alone.
	if _, changed, err = Run(ctx, s, policy, now, true); err != nil || changed {
		t.Fatalf("second init: %v %v", changed, err)
	}
	if _, changed, err = Run(ctx, s, policy, now, false); err != nil || changed {
		t.Fatalf("rotate when up to date: %v %v", changed, err)
	}

	s.conflicts = maxAttempts
	if _, _, err := Run(ctx, s, policy, func() time.Time { return now().Add(29 * 24 * time.Hour) }, false); !errors.Is(err, wag.ErrConflict) {
		t.Fatalf("err = %v, want conflict after retries", err)
	}
}
