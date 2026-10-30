package app

import (
	"context"
	"time"

	"github.com/defakto-security/wag-k8s/internal/config"
	"github.com/defakto-security/wag-k8s/internal/keys"
	"github.com/defakto-security/wag-k8s/internal/rotation"
)

// RotateOptions are the rotate command's options.
type RotateOptions struct {
	ConfigPath string
	Kubeconfig string
	// InitOnly creates the first key set and leaves an existing one alone.
	InitOnly bool
}

// RunRotate advances the signing keys once and exits. It is meant to run as a
// CronJob with concurrencyPolicy Forbid, and with InitOnly as an install hook.
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
	_, _, err = rotation.Run(ctx, store, rotation.Policy{
		Cluster:     cfg.Cluster.Name,
		Algorithm:   cfg.Keys.Algorithm,
		RotateEvery: cfg.Keys.RotateEvery.Duration,
		Overlap:     cfg.Keys.Overlap.Duration,
		MaxTTL:      cfg.Token.MaxTTL.Duration,
	}, time.Now, opts.InitOnly)
	return err
}
