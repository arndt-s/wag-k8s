// Command wag-k8s issues Workload Authorization Grants to Kubernetes workloads.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/arndt-s/wag-k8s/internal/app"
)

const usage = `usage: wag-k8s <command> [flags]

commands:
  issuer   run the token exchange endpoint and serve issuer metadata
`

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "issuer":
		err = app.RunIssuer(ctx, os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}
