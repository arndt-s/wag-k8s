// Package app wires the components into the wag-k8s subcommands.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/defakto-security/wag-k8s/internal/config"
	"github.com/defakto-security/wag-k8s/internal/keys"
	"github.com/defakto-security/wag-k8s/internal/metadata"
	"github.com/defakto-security/wag-k8s/internal/policy"
	"github.com/defakto-security/wag-k8s/internal/server"
	"github.com/defakto-security/wag-k8s/internal/signer"
	"github.com/defakto-security/wag-k8s/internal/subject"
	"github.com/defakto-security/wag-k8s/internal/telemetry"
	"github.com/defakto-security/wag-k8s/internal/validator"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

// IssuerOptions are the issuer's command-line options.
type IssuerOptions struct {
	ConfigPath string
	Kubeconfig string
	Version    string
}

// RunIssuer runs the issuer until ctx is done.
func RunIssuer(ctx context.Context, opts IssuerOptions) error {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}
	client, err := kubeClient(opts.Kubeconfig)
	if err != nil {
		return err
	}
	shutdownTelemetry, err := telemetry.Setup(ctx, opts.Version)
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTelemetry(ctx)
	}()

	iss, ingressSource, err := issuerSource(ctx, cfg, client)
	if err != nil {
		return err
	}
	issuerURL, _ := iss.Issuer(ctx)
	renderer, err := subject.NewTemplateRenderer(cfg.Cluster.TrustDomain, cfg.Cluster.Name, cfg.Subject.Template, cfg.Subject.NicknameTemplate)
	if err != nil {
		return err
	}
	keyCache := keys.NewCache(keys.NewSecretStore(client, cfg.Keys.Secret.Namespace, cfg.Keys.Secret.Name), 30*time.Second)
	sign := signer.New(keyCache.Get)

	var v wag.Validator = validator.NewTokenReview(client, cfg.ServiceAccountToken.Audiences, cfg.ServiceAccountToken.CacheTTL.Duration)
	if cfg.Token.Claims.WantsPodMetadata() {
		v = validator.NewPodMetadata(v, client, cfg.Token.Claims.PodLabelPrefixes, cfg.Token.Claims.PodAnnotationPrefixes)
	}
	exchanger := &server.Exchanger{
		Validator: v,
		Policy:    policy.NewRules(cfg.Policy.Rules),
		Subjects:  renderer,
		Issuer:    iss,
		Signer:    sign,
		TTL:       cfg.Token.TTL.Duration,
		Cluster:   cfg.Cluster.Name,
		Audit:     slog.Default().With("log", "audit"),
		Now:       time.Now,
	}

	g, ctx := errgroup.WithContext(ctx)
	if ingressSource != nil {
		g.Go(func() error { ingressSource.Check(ctx, time.Minute); return nil })
	}

	if cfg.Publish.Serve {
		docs := &server.Documents{CacheControl: cfg.Publish.CacheControl}
		paths, err := metadata.PathsFor(issuerURL)
		if err != nil {
			return err
		}
		keyCache.OnChange(func(ks *keys.KeySet) {
			meta, jwks, err := metadata.Render(issuerURL, cfg.Issuer.InternalTokenEndpoint, ks)
			if err != nil {
				slog.Error("rendering metadata", "err", err)
				return
			}
			docs.Swap(paths.Metadata, paths.JWKS, meta, jwks)
		})
		g.Go(func() error { return serve(ctx, "public", cfg.Server.PublicAddr, docs, config.TLS{}) })
	}

	tokenMux := http.NewServeMux()
	tokenMux.Handle("/token", &server.TokenHandler{Exchanger: exchanger})
	if cfg.Server.TokenTLS.CertFile == "" {
		slog.Warn("token endpoint serves plain HTTP; service account tokens cross the network unencrypted unless a mesh adds TLS")
	}
	g.Go(func() error { return serve(ctx, "token", cfg.Server.TokenAddr, tokenMux, cfg.Server.TokenTLS) })

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	adminMux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !sign.Ready() {
			http.Error(w, "no signing key", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	adminMux.Handle("/metrics", promhttp.Handler())
	g.Go(func() error { return serve(ctx, "admin", cfg.Server.AdminAddr, adminMux, config.TLS{}) })

	g.Go(func() error {
		err := keyCache.Run(ctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	})

	slog.Info("issuer started", "issuer", issuerURL, "cluster", cfg.Cluster.Name, "mode", cfg.Publish.Mode)
	return g.Wait()
}

func serve(ctx context.Context, name, addr string, h http.Handler, tls config.TLS) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "server", name, "addr", addr, "tls", tls.CertFile != "")
		if tls.CertFile != "" {
			errc <- srv.ListenAndServeTLS(tls.CertFile, tls.KeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return fmt.Errorf("%s server: %w", name, err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func kubeClient(kubeconfig string) (kubernetes.Interface, error) {
	var (
		rc  *rest.Config
		err error
	)
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}
	if kubeconfig != "" {
		rc, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		rc, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes client config: %w", err)
	}
	rc.UserAgent = "wag-k8s"
	return kubernetes.NewForConfig(rc)
}
