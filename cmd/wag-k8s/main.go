// Command wag-k8s issues Workload Authorization Grants to Kubernetes workloads.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/defakto-security/wag-k8s/internal/app"
	"github.com/defakto-security/wag-k8s/internal/csi"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "wag-k8s",
		Short:         "Issue Workload Authorization Grants to Kubernetes workloads",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newIssuerCommand(), newRotateCommand(), newCSICommand())
	return root
}

func newIssuerCommand() *cobra.Command {
	opts := app.IssuerOptions{Version: version}
	cmd := &cobra.Command{
		Use:   "issuer",
		Short: "Run the token exchange endpoint and serve issuer metadata",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.RunIssuer(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.ConfigPath, "config", "/etc/wag-k8s/config.yaml", "path to the config file")
	cmd.Flags().StringVar(&opts.Kubeconfig, "kubeconfig", "", "path to a kubeconfig; in-cluster config when empty (also read from KUBECONFIG)")
	return cmd
}

func newRotateCommand() *cobra.Command {
	var opts app.RotateOptions
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Advance the signing keys once: create, publish next, promote, retire",
		Long: `Advance the signing keys once and exit. Run it on a schedule (a CronJob
with concurrencyPolicy Forbid); it is the only writer of the key store.
With --init-only it creates the first key set if none exists and otherwise
does nothing, for use as an install hook.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.RunRotate(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.ConfigPath, "config", "/etc/wag-k8s/config.yaml", "path to the config file")
	cmd.Flags().StringVar(&opts.Kubeconfig, "kubeconfig", "", "path to a kubeconfig; in-cluster config when empty (also read from KUBECONFIG)")
	cmd.Flags().BoolVar(&opts.InitOnly, "init-only", false, "only create the first key set (leave an existing one alone) and publish nothing")
	return cmd
}

func newCSICommand() *cobra.Command {
	opts := app.CSIOptions{Version: version}
	cmd := &cobra.Command{
		Use:   "csi",
		Short: "Run the CSI node plugin that keeps a fresh grant on disk for a pod",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.RunCSI(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.Endpoint, "endpoint", "unix:///csi/csi.sock", "CSI endpoint (unix socket)")
	cmd.Flags().StringVar(&opts.DriverName, "driver-name", csi.DefaultName, "CSI driver name; must match the CSIDriver object")
	cmd.Flags().StringVar(&opts.NodeID, "node-id", os.Getenv("NODE_NAME"), "node name (defaults to NODE_NAME)")
	cmd.Flags().StringVar(&opts.TokenEndpoint, "token-endpoint", "", "issuer token endpoint, e.g. https://wag-k8s.wag-system.svc:8443/token")
	cmd.Flags().StringVar(&opts.CAFile, "ca-file", "", "extra CA bundle for the token endpoint")
	cmd.Flags().StringVar(&opts.SATAudience, "sat-audience", "wag-k8s", "audience of the service account token kubelet requests for the driver (CSIDriver tokenRequests)")
	return cmd
}
