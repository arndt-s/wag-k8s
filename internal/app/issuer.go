// Package app wires the components into the wag-k8s subcommands.
package app

import (
	"context"
	"errors"
	"flag"
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

	"github.com/arndt-s/wag-k8s/internal/config"
	"github.com/arndt-s/wag-k8s/internal/issuer"
	"github.com/arndt-s/wag-k8s/internal/keys"
	"github.com/arndt-s/wag-k8s/internal/metadata"
	"github.com/arndt-s/wag-k8s/internal/policy"
	"github.com/arndt-s/wag-k8s/internal/server"
	"github.com/arndt-s/wag-k8s/internal/signer"
	"github.com/arndt-s/wag-k8s/internal/subject"
	"github.com/arndt-s/wag-k8s/internal/validator"
)

// documentCacheControl bounds how long authorization servers and CDNs cache
// metadata and JWKS. keys.overlap must stay well above it.
const documentCacheControl = "public, max-age=300"

// RunIssuer runs the issuer until ctx is done.
func RunIssuer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("issuer", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/wag-k8s/config.yaml", "path to the config file")
	kubeconfig := fs.String("kubeconfig", "", "path to a kubeconfig; in-cluster config when empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	client, err := kubeClient(*kubeconfig)
	if err != nil {
		return err
	}

	iss, err := issuer.NewStatic(cfg.Issuer.URL)
	if err != nil {
		return err
	}
	renderer, err := subject.NewTemplateRenderer(cfg.Subject.TrustDomain, cfg.Cluster.Name, cfg.Subject.Template, cfg.Subject.NicknameTemplate)
	if err != nil {
		return err
	}
	keyCache := keys.NewCache(keys.NewSecretStore(client, cfg.Keys.Secret.Namespace, cfg.Keys.Secret.Name), 30*time.Second)
	sign := signer.New(keyCache.Get)

	exchanger := &server.Exchanger{
		Validator:   validator.NewTokenReview(client, cfg.SAT.Audiences, cfg.SAT.CacheTTL.Duration),
		Policy:      policy.NewRules(cfg.Policy.Rules),
		Subjects:    renderer,
		Issuer:      iss,
		Signer:      sign,
		TTL:         cfg.Token.TTL.Duration,
		ExtraClaims: cfg.Token.ExtraClaims,
		Audit:       slog.Default().With("log", "audit"),
		Now:         time.Now,
	}

	g, ctx := errgroup.WithContext(ctx)

	if cfg.Publish.Serve {
		docs := &server.Documents{CacheControl: documentCacheControl}
		paths, err := metadata.PathsFor(cfg.Issuer.URL)
		if err != nil {
			return err
		}
		keyCache.OnChange(func(ks *keys.KeySet) {
			meta, jwks, err := metadata.Render(cfg.Issuer.URL, cfg.Issuer.TokenEndpoint, ks)
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

	slog.Info("issuer started", "issuer", cfg.Issuer.URL, "cluster", cfg.Cluster.Name, "mode", cfg.Publish.Mode)
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
