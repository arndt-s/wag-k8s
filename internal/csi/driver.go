// Package csi implements a CSI node plugin that keeps a fresh Workload
// Authorization Grant on disk for a pod. It only supports ephemeral inline
// volumes; kubelet hands it a service account token on every publish
// (CSIDriver tokenRequests) and calls it again periodically
// (requiresRepublish).
package csi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
	mount "k8s.io/mount-utils"
)

// DefaultName is the driver name pods put in their csi volume. It is
// deliberately generic so that any WAG CSI driver can take its place without
// changing pod specs; --driver-name overrides it.
const DefaultName = "wag"

const (
	// Volume attributes set by the pod.
	AttrAudience = "audience"
	AttrScope    = "scope"
	AttrFileName = "fileName"

	defaultFileName = "token"
	// refreshAt is the fraction of a grant's lifetime after which it is
	// replaced.
	refreshAt = 0.5

	// Volume context keys set by kubelet.
	ctxTokens    = "csi.storage.k8s.io/serviceAccount.tokens"
	ctxEphemeral = "csi.storage.k8s.io/ephemeral"
	ctxPodNS     = "csi.storage.k8s.io/pod.namespace"
	ctxPodName   = "csi.storage.k8s.io/pod.name"
)

// Driver is the CSI identity and node service.
type Driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedNodeServer

	Name    string
	Version string
	NodeID  string
	// SATAudience picks the token kubelet requested for the issuer.
	SATAudience string
	Exchanger   Exchanger
	Mounter     mount.Interface
	Now         func() time.Time
}

func (d *Driver) GetPluginInfo(context.Context, *csi.GetPluginInfoRequest) (*csi.GetPluginInfoResponse, error) {
	return &csi.GetPluginInfoResponse{Name: d.Name, VendorVersion: d.Version}, nil
}

func (d *Driver) GetPluginCapabilities(context.Context, *csi.GetPluginCapabilitiesRequest) (*csi.GetPluginCapabilitiesResponse, error) {
	// Node plugin only: no controller service.
	return &csi.GetPluginCapabilitiesResponse{}, nil
}

func (d *Driver) Probe(context.Context, *csi.ProbeRequest) (*csi.ProbeResponse, error) {
	return &csi.ProbeResponse{Ready: wrapperspb.Bool(true)}, nil
}

func (d *Driver) NodeGetInfo(context.Context, *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{NodeId: d.NodeID}, nil
}

func (d *Driver) NodeGetCapabilities(context.Context, *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	// VOLUME_MOUNT_GROUP: kubelet passes the pod's fsGroup and leaves
	// ownership to us, so republished files keep the right group.
	return &csi.NodeGetCapabilitiesResponse{Capabilities: []*csi.NodeServiceCapability{{
		Type: &csi.NodeServiceCapability_Rpc{Rpc: &csi.NodeServiceCapability_RPC{Type: csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP}},
	}}}, nil
}

// volume is a validated NodePublishVolume request.
type volume struct {
	target   string
	audience string
	scopes   []string
	fileName string
	sat      string
	gid      int
	pod      string
}

func parseRequest(req *csi.NodePublishVolumeRequest, satAudience string) (*volume, error) {
	bad := func(format string, a ...any) error { return status.Errorf(codes.InvalidArgument, format, a...) }
	vc := req.GetVolumeContext()
	if req.GetTargetPath() == "" {
		return nil, bad("target path is required")
	}
	if vc[ctxEphemeral] != "true" {
		return nil, bad("only ephemeral inline volumes are supported")
	}
	if req.GetVolumeCapability().GetMount() == nil {
		return nil, bad("only mount volumes are supported")
	}
	if !req.GetReadonly() {
		return nil, bad("volume must be readOnly")
	}
	v := &volume{
		target:   req.GetTargetPath(),
		audience: vc[AttrAudience],
		scopes:   strings.Fields(vc[AttrScope]),
		fileName: vc[AttrFileName],
		gid:      -1,
		pod:      vc[ctxPodNS] + "/" + vc[ctxPodName],
	}
	if v.audience == "" {
		return nil, bad("volume attribute %q is required", AttrAudience)
	}
	if v.fileName == "" {
		v.fileName = defaultFileName
	}
	if v.fileName != filepath.Base(v.fileName) || v.fileName == "." || v.fileName == ".." || strings.HasPrefix(v.fileName, ".") {
		return nil, bad("volume attribute %q must be a plain file name", AttrFileName)
	}
	if g := req.GetVolumeCapability().GetMount().GetVolumeMountGroup(); g != "" {
		gid, err := strconv.Atoi(g)
		if err != nil || gid < 0 {
			return nil, bad("invalid volume mount group %q", g)
		}
		v.gid = gid
	}

	var tokens map[string]struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(vc[ctxTokens]), &tokens); err != nil {
		return nil, bad("no service account token from kubelet; the CSIDriver needs tokenRequests for audience %q", satAudience)
	}
	v.sat = tokens[satAudience].Token
	if v.sat == "" {
		return nil, bad("no service account token for audience %q; check the CSIDriver tokenRequests", satAudience)
	}
	return v, nil
}

func (d *Driver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	v, err := parseRequest(req, d.SATAudience)
	if err != nil {
		return nil, err
	}
	if err := d.ensureMount(v); err != nil {
		return nil, status.Errorf(codes.Internal, "mount %s: %v", v.target, err)
	}

	path := filepath.Join(v.target, v.fileName)
	if !needsRefresh(path, d.Now(), refreshAt) {
		return &csi.NodePublishVolumeResponse{}, nil
	}
	grant, err := d.Exchanger.Exchange(ctx, v.sat, v.audience, v.scopes)
	if err != nil {
		// Any grant already on disk stays until a new one lands; kubelet
		// retries the publish.
		slog.Warn("exchange failed", "pod", v.pod, "audience", v.audience, "err", err)
		return nil, status.Errorf(codes.Unavailable, "exchange service account token: %v", err)
	}
	if err := writeAtomic(v.target, v.fileName, []byte(grant), v.gid); err != nil {
		return nil, status.Errorf(codes.Internal, "write grant: %v", err)
	}
	slog.Info("grant written", "pod", v.pod, "audience", v.audience, "file", v.fileName)
	return &csi.NodePublishVolumeResponse{}, nil
}

// ensureMount puts a small tmpfs at the target so grants never touch the
// node's disk. It is a no-op when the tmpfs is already there.
func (d *Driver) ensureMount(v *volume) error {
	if err := os.MkdirAll(v.target, 0o750); err != nil {
		return err
	}
	notMnt, err := d.Mounter.IsLikelyNotMountPoint(v.target)
	if err != nil {
		return err
	}
	if !notMnt {
		return nil
	}
	opts := []string{"size=1m", "mode=0755"}
	if v.gid >= 0 {
		opts = []string{"size=1m", "mode=0750", fmt.Sprintf("gid=%d", v.gid)}
	}
	return d.Mounter.Mount("tmpfs", v.target, "tmpfs", opts)
}

func (d *Driver) NodeUnpublishVolume(_ context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	if req.GetTargetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	}
	target := req.GetTargetPath()
	notMnt, err := d.Mounter.IsLikelyNotMountPoint(target)
	switch {
	case os.IsNotExist(err):
		return &csi.NodeUnpublishVolumeResponse{}, nil
	case err != nil:
		return nil, status.Errorf(codes.Internal, "check mount %s: %v", target, err)
	case !notMnt:
		if err := d.Mounter.Unmount(target); err != nil {
			return nil, status.Errorf(codes.Internal, "unmount %s: %v", target, err)
		}
	}
	// Unmounting dropped the grant with the tmpfs; this removes the empty
	// directory, or the files if the mount was already gone.
	if err := os.RemoveAll(target); err != nil {
		return nil, status.Errorf(codes.Internal, "remove %s: %v", target, err)
	}
	return &csi.NodeUnpublishVolumeResponse{}, nil
}
