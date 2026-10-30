package csi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
)

// Serve runs the driver on a unix socket endpoint such as
// unix:///csi/csi.sock until ctx is done.
func Serve(ctx context.Context, endpoint string, d *Driver) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "unix" || u.Path == "" {
		return fmt.Errorf("endpoint must be unix:///path/to/socket, got %q", endpoint)
	}
	if err := os.Remove(u.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lis, err := net.Listen("unix", u.Path)
	if err != nil {
		return err
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(logErrors))
	csi.RegisterIdentityServer(srv, d)
	csi.RegisterNodeServer(srv, d)
	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()
	slog.Info("csi driver listening", "endpoint", endpoint, "driver", d.Name, "node", d.NodeID)
	return srv.Serve(lis)
}

func logErrors(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	resp, err := h(ctx, req)
	if err != nil {
		slog.Error("csi call failed", "method", info.FullMethod, "err", err)
	}
	return resp, err
}
