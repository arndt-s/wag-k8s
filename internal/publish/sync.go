package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/defakto-security/wag-k8s/internal/keys"
	"github.com/defakto-security/wag-k8s/internal/metadata"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

const (
	contentType      = "application/json"
	maxDocumentBytes = 1 << 20
	maxAttempts      = 5
)

// Target is one Publisher, named for logs.
type Target interface {
	wag.Publisher
	fmt.Stringer
}

// Syncer publishes this cluster's documents.
type Syncer struct {
	Issuer        string
	TokenEndpoint string
	Cluster       string
	// Shared merges this cluster's keys into a JWKS other clusters also
	// write; otherwise this cluster owns the whole document.
	Shared bool
}

// Sync publishes metadata and JWKS for ks to every target. It writes only
// what changed and returns the first error after trying all targets.
func (s *Syncer) Sync(ctx context.Context, ks *keys.KeySet, targets []Target) error {
	tokenEndpoint := s.TokenEndpoint
	if s.Shared {
		// Each cluster has its own in-cluster endpoint; the shared document
		// cannot name one.
		tokenEndpoint = ""
	}
	meta, jwks, err := metadata.Render(s.Issuer, tokenEndpoint, ks)
	if err != nil {
		return err
	}
	paths, err := metadata.PathsFor(s.Issuer)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range targets {
		if err := s.syncOne(ctx, t, paths, meta, jwks, ks); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Syncer) syncOne(ctx context.Context, t Target, paths metadata.Paths, meta, jwks []byte, ks *keys.KeySet) error {
	if !s.Shared {
		if err := putIfChanged(ctx, t, paths.Metadata, meta); err != nil {
			return err
		}
		return putIfChanged(ctx, t, paths.JWKS, jwks)
	}
	if err := ensureSharedMetadata(ctx, t, paths.Metadata, meta); err != nil {
		return err
	}
	return mergeJWKS(ctx, t, paths.JWKS, s.Cluster, ks.PublicJWKS())
}

// putIfChanged writes body unless the object already holds it.
func putIfChanged(ctx context.Context, t Target, path string, body []byte) error {
	old, _, err := t.Get(ctx, path)
	if err != nil && !errors.Is(err, wag.ErrNotFound) {
		return err
	}
	if bytes.Equal(old, body) {
		return nil
	}
	if err := t.Put(ctx, path, contentType, bytes.NewReader(body), wag.Condition{}); err != nil {
		return err
	}
	slog.Info("published", "target", t.String(), "path", path)
	return nil
}

// ensureSharedMetadata creates the metadata document if it is missing. It
// never overwrites an existing one: clusters on different versions would
// otherwise take turns rewriting it.
func ensureSharedMetadata(ctx context.Context, t Target, path string, body []byte) error {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		old, _, err := t.Get(ctx, path)
		switch {
		case errors.Is(err, wag.ErrNotFound):
			err = t.Put(ctx, path, contentType, bytes.NewReader(body), wag.Condition{IfNoneMatch: true})
			if errors.Is(err, wag.ErrConflict) {
				continue // another cluster created it; compare on the next pass
			}
			if err == nil {
				slog.Info("published", "target", t.String(), "path", path)
			}
			return err
		case err != nil:
			return err
		}
		if !jsonEqual(old, body) {
			slog.Warn("shared metadata differs from this cluster's, leaving it as is", "target", t.String(), "path", path)
		}
		return nil
	}
	return fmt.Errorf("metadata at %s: %w after %d attempts", path, wag.ErrConflict, maxAttempts)
}

// mergeJWKS replaces this cluster's keys in a JWKS shared with other
// clusters, using ETag compare-and-swap. Keys are this cluster's when their
// kid starts with "<cluster>/".
func mergeJWKS(ctx context.Context, t Target, path, cluster string, own jose.JSONWebKeySet) error {
	prefix := cluster + "/"
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		old, etag, err := t.Get(ctx, path)
		exists := true
		switch {
		case errors.Is(err, wag.ErrNotFound):
			exists = false
		case err != nil:
			return err
		}

		var current jose.JSONWebKeySet
		if exists {
			// Refuse to overwrite what we cannot read: it would drop every
			// other cluster's keys.
			if err := json.Unmarshal(old, &current); err != nil {
				return fmt.Errorf("existing JWKS at %s is unreadable, not overwriting: %w", path, err)
			}
		}
		var foreign []jose.JSONWebKey
		for _, k := range current.Keys {
			if !strings.HasPrefix(k.KeyID, prefix) {
				foreign = append(foreign, k)
			}
		}
		merged := append(slices.Clone(foreign), own.Keys...)
		slices.SortStableFunc(merged, func(a, b jose.JSONWebKey) int { return strings.Compare(a.KeyID, b.KeyID) })
		body, err := json.Marshal(jose.JSONWebKeySet{Keys: merged})
		if err != nil {
			return err
		}
		if exists && bytes.Equal(old, body) {
			return nil
		}
		if n := countForeign(merged, prefix); n < len(foreign) {
			return fmt.Errorf("refusing to publish a JWKS that drops other clusters' keys (%d of %d kept)", n, len(foreign))
		}

		cond := wag.Condition{IfMatch: etag, IfNoneMatch: !exists}
		err = t.Put(ctx, path, contentType, bytes.NewReader(body), cond)
		if errors.Is(err, wag.ErrConflict) {
			slog.Info("JWKS changed while merging, retrying", "target", t.String(), "attempt", attempt)
			continue
		}
		if err != nil {
			return err
		}
		slog.Info("published", "target", t.String(), "path", path, "ownKeys", len(own.Keys), "otherKeys", len(foreign))
		return nil
	}
	return fmt.Errorf("JWKS at %s: %w after %d attempts", path, wag.ErrConflict, maxAttempts)
}

func countForeign(ks []jose.JSONWebKey, prefix string) int {
	n := 0
	for _, k := range ks {
		if !strings.HasPrefix(k.KeyID, prefix) {
			n++
		}
	}
	return n
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}
