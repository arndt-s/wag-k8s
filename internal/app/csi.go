package app

import (
	"context"
	"errors"
	"time"

	mount "k8s.io/mount-utils"

	"github.com/defakto-security/wag-k8s/internal/csi"
)

// CSIOptions are the csi command's options.
type CSIOptions struct {
	Endpoint      string
	DriverName    string
	NodeID        string
	TokenEndpoint string
	CAFile        string
	SATAudience   string
	Version       string
}

// RunCSI runs the CSI node plugin until ctx is done.
func RunCSI(ctx context.Context, opts CSIOptions) error {
	if opts.NodeID == "" {
		return errors.New("--node-id is required (usually from the NODE_NAME env var)")
	}
	if opts.TokenEndpoint == "" {
		return errors.New("--token-endpoint is required")
	}
	ex, err := csi.NewHTTPExchanger(opts.TokenEndpoint, opts.CAFile)
	if err != nil {
		return err
	}
	return csi.Serve(ctx, opts.Endpoint, &csi.Driver{
		Name:        opts.DriverName,
		Version:     opts.Version,
		NodeID:      opts.NodeID,
		SATAudience: opts.SATAudience,
		Exchanger:   ex,
		Mounter:     mount.New(""),
		Now:         time.Now,
	})
}
