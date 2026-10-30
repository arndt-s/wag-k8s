package keys

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defakto-security/wag-k8s/internal/wag"
)

// Cache holds the latest valid key set for the issuer and tells listeners when
// it changes.
type Cache struct {
	store        KeyStore
	pollInterval time.Duration

	current   atomic.Pointer[KeySet]
	mu        sync.Mutex
	listeners []func(*KeySet)
}

func NewCache(store KeyStore, pollInterval time.Duration) *Cache {
	return &Cache{store: store, pollInterval: pollInterval}
}

// Get returns the latest valid key set, or nil before the first one arrived.
func (c *Cache) Get() *KeySet { return c.current.Load() }

// OnChange registers fn to run after every accepted key set.
func (c *Cache) OnChange(fn func(*KeySet)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listeners = append(c.listeners, fn)
}

// Set accepts ks if it is valid; invalid key sets are logged and ignored so
// the issuer keeps signing with the last good one.
func (c *Cache) Set(ks *KeySet) {
	if err := ks.Validate(); err != nil {
		slog.Error("ignoring invalid key set", "version", ks.Version, "err", err)
		return
	}
	if old := c.current.Load(); old != nil && old.Version != "" && old.Version == ks.Version {
		return
	}
	c.current.Store(ks)
	slog.Info("loaded signing keys", "version", ks.Version, "current", ks.Current().ID, "keys", len(ks.Keys))
	c.mu.Lock()
	ls := append([]func(*KeySet){}, c.listeners...)
	c.mu.Unlock()
	for _, fn := range ls {
		fn(ks)
	}
}

// Run keeps the cache fresh until ctx is done, by watching when the store
// supports it and by polling otherwise.
func (c *Cache) Run(ctx context.Context) error {
	if w, ok := c.store.(Watcher); ok {
		return w.Watch(ctx, c.Set)
	}
	t := time.NewTicker(c.pollInterval)
	defer t.Stop()
	for {
		ks, err := c.store.Load(ctx)
		switch {
		case err == nil:
			c.Set(ks)
		case errors.Is(err, wag.ErrNotFound):
			slog.Info("no signing keys yet")
		default:
			slog.Warn("loading signing keys", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
