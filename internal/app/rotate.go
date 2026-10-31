package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/defakto-security/wag-k8s/internal/config"
	"github.com/defakto-security/wag-k8s/internal/keys"
	"github.com/defakto-security/wag-k8s/internal/publish"
	"github.com/defakto-security/wag-k8s/internal/rotation"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

// RotateOptions are the rotate command's options.
type RotateOptions struct {
	ConfigPath string
	Kubeconfig string
	// InitOnly creates the first key set and leaves an existing one alone.
	InitOnly bool
}

// RunRotate advances the signing keys once, publishes metadata and JWKS to the
// configured sinks, and exits. It is meant to run as a CronJob with
// concurrencyPolicy Forbid, and with InitOnly as an install hook, which only
// creates the first key set and publishes nothing.
func RunRotate(ctx context.Context, opts RotateOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	client, err := kubeClient(opts.Kubeconfig)
	if err != nil {
		return err
	}
	store := keys.NewSecretStore(client, cfg.Keys.Secret.Namespace, cfg.Keys.Secret.Name)
	sync := func(context.Context, *keys.KeySet) error { return nil }
	if !opts.InitOnly {
		if sync, err = newSync(ctx, cfg, client); err != nil {
			return err
		}
	}

	// Publish what is stored before changing it: a next key must be
	// published before it is promoted, so while the sinks are unreachable
	// the job fails here and the current key keeps signing.
	if !opts.InitOnly {
		ks, err := store.Load(ctx)
		switch {
		case errors.Is(err, wag.ErrNotFound):
		case err != nil:
			return err
		default:
			if err := sync(ctx, ks); err != nil {
				return fmt.Errorf("publish before rotating: %w", err)
			}
		}
	}

	ks, _, err := rotation.Run(ctx, store, rotation.Policy{
		Cluster:     cfg.Cluster.Name,
		Algorithm:   cfg.Keys.Algorithm,
		RotateEvery: cfg.Keys.RotateEvery.Duration,
		Overlap:     cfg.Keys.Overlap.Duration,
		MaxTTL:      cfg.Token.MaxTTL.Duration,
	}, time.Now, opts.InitOnly)
	if err != nil {
		return err
	}
	if opts.InitOnly {
		// The install hook runs before the rest of the release exists (an
		// Ingress the issuer is derived from, cloud credentials); the
		// first scheduled run publishes.
		return nil
	}
	// Publish on every run, not only on change, so a failed publish is
	// retried by the next run.
	return sync(ctx, ks)
}

// newSync returns a function that publishes a key set to the configured
// sinks, or does nothing when there are none.
func newSync(ctx context.Context, cfg *config.Config, client kubernetes.Interface) (func(context.Context, *keys.KeySet) error, error) {
	if len(cfg.Publish.Sinks) == 0 {
		return func(context.Context, *keys.KeySet) error { return nil }, nil
	}
	targets, err := publishTargets(ctx, cfg)
	if err != nil {
		return nil, err
	}
	iss, _, err := issuerSource(ctx, cfg, client)
	if err != nil {
		return nil, err
	}
	issuerURL, err := iss.Issuer(ctx)
	if err != nil {
		return nil, err
	}
	syncer := &publish.Syncer{
		Issuer:        issuerURL,
		TokenEndpoint: cfg.Issuer.InternalTokenEndpoint,
		Cluster:       cfg.Cluster.Name,
		Shared:        cfg.Publish.Mode == config.ModeShared,
	}
	return func(ctx context.Context, ks *keys.KeySet) error { return syncer.Sync(ctx, ks, targets) }, nil
}
