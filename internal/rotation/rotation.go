// Package rotation advances a key set through its lifecycle. It is the only
// writer of the key store; issuers only read.
package rotation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/defakto-security/wag-k8s/internal/keys"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

// Policy is when keys change.
type Policy struct {
	Cluster   string
	Algorithm string
	// RotateEvery is how long a key stays current.
	RotateEvery time.Duration
	// Overlap is how long a key is published before it signs, and how long
	// it stays published after it stops signing, on top of MaxTTL.
	Overlap time.Duration
	// MaxTTL is the longest lifetime of a grant.
	MaxTTL time.Duration
}

// Change describes one step Plan took.
type Change struct {
	Action string // created, added-next, promoted, removed
	KeyID  string
}

// Plan returns the key set after every step that is due at now, and what
// changed. It never mutates ks. Running it again right away changes nothing.
//
// The steps, each driven by the key's StateChangedAt:
//   - no current key: create one (bootstrap), or promote next if there is one
//   - current is due within Overlap and there is no next key: add a next key
//   - next has been published for Overlap: promote it, demote current
//   - previous stopped signing more than Overlap + MaxTTL ago: remove it
func Plan(ks *keys.KeySet, p Policy, now time.Time) (*keys.KeySet, []Change, error) {
	out := &keys.KeySet{Version: ks.Version, Keys: slices.Clone(ks.Keys)}
	var changes []Change

	find := func(s keys.State) int {
		return slices.IndexFunc(out.Keys, func(k keys.Key) bool { return k.State == s })
	}
	setState := func(i int, s keys.State) {
		out.Keys[i].State = s
		out.Keys[i].StateChangedAt = now.UTC().Truncate(time.Second)
	}

	if find(keys.StateCurrent) < 0 {
		if i := find(keys.StateNext); i >= 0 {
			setState(i, keys.StateCurrent)
			changes = append(changes, Change{"promoted", out.Keys[i].ID})
		} else {
			k, err := keys.Generate(p.Cluster, p.Algorithm, keys.StateCurrent, now)
			if err != nil {
				return nil, nil, err
			}
			out.Keys = append(out.Keys, k)
			changes = append(changes, Change{"created", k.ID})
		}
	}

	cur, next := find(keys.StateCurrent), find(keys.StateNext)
	if next >= 0 && !now.Before(out.Keys[next].StateChangedAt.Add(p.Overlap)) {
		setState(cur, keys.StatePrevious)
		setState(next, keys.StateCurrent)
		changes = append(changes, Change{"promoted", out.Keys[next].ID})
		cur, next = next, -1
	}
	if next < 0 && !now.Before(out.Keys[cur].StateChangedAt.Add(p.RotateEvery-p.Overlap)) {
		k, err := keys.Generate(p.Cluster, p.Algorithm, keys.StateNext, now)
		if err != nil {
			return nil, nil, err
		}
		out.Keys = append(out.Keys, k)
		changes = append(changes, Change{"added-next", k.ID})
	}

	out.Keys = slices.DeleteFunc(out.Keys, func(k keys.Key) bool {
		if k.State == keys.StatePrevious && !now.Before(k.StateChangedAt.Add(p.Overlap+p.MaxTTL)) {
			changes = append(changes, Change{"removed", k.ID})
			return true
		}
		return false
	})

	if err := out.Validate(); err != nil {
		return nil, nil, fmt.Errorf("planned key set is invalid: %w", err)
	}
	return out, changes, nil
}

// maxAttempts bounds retries when another writer saves first.
const maxAttempts = 5

// Run loads the key set, applies Plan and saves it with compare-and-swap,
// retrying on conflict. With initOnly, it only creates a key set when none
// exists. It returns the saved key set and whether anything changed.
func Run(ctx context.Context, store keys.KeyStore, p Policy, now func() time.Time, initOnly bool) (*keys.KeySet, bool, error) {
	for attempt := 1; ; attempt++ {
		ks, err := store.Load(ctx)
		switch {
		case errors.Is(err, wag.ErrNotFound):
			ks = &keys.KeySet{}
		case err != nil:
			return nil, false, fmt.Errorf("load keys: %w", err)
		case initOnly:
			slog.Info("key set exists, nothing to initialize", "version", ks.Version)
			return ks, false, nil
		}

		planned, changes, err := Plan(ks, p, now())
		if err != nil {
			return nil, false, err
		}
		if len(changes) == 0 {
			slog.Info("keys are up to date", "current", planned.Current().ID)
			return planned, false, nil
		}
		err = store.Save(ctx, planned, ks.Version)
		if errors.Is(err, wag.ErrConflict) && attempt < maxAttempts {
			slog.Warn("key set changed while rotating, retrying", "attempt", attempt)
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("save keys: %w", err)
		}
		for _, c := range changes {
			slog.Info("key rotation", "action", c.Action, "kid", c.KeyID)
		}
		return planned, true, nil
	}
}
