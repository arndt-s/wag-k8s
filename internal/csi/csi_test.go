package csi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	mount "k8s.io/mount-utils"

	"github.com/defakto-security/wag-k8s/internal/wag"
)

var t0 = time.Unix(1_800_000_000, 0)

func fakeJWT(iat, exp time.Time) string {
	p, _ := json.Marshal(map[string]int64{"iat": iat.Unix(), "exp": exp.Unix()})
	return "e30." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

type fakeExchanger struct {
	calls  int
	err    error
	ttl    time.Duration
	now    func() time.Time
	gotSAT string
	gotAud string
	gotSc  []string
}

func (f *fakeExchanger) Exchange(_ context.Context, sat, aud string, scopes []string) (string, error) {
	f.calls++
	f.gotSAT, f.gotAud, f.gotSc = sat, aud, scopes
	if f.err != nil {
		return "", f.err
	}
	n := f.now()
	return fakeJWT(n, n.Add(f.ttl)), nil
}

func newDriver(t *testing.T) (*Driver, *fakeExchanger, *time.Time) {
	now := t0
	ex := &fakeExchanger{ttl: 10 * time.Minute, now: func() time.Time { return now }}
	return &Driver{
		Name:        "wag-k8s.defakto.security",
		NodeID:      "node-1",
		SATAudience: "wag-k8s",
		Exchanger:   ex,
		Mounter:     mount.NewFakeMounter(nil),
		Now:         func() time.Time { return now },
	}, ex, &now
}

func publishReq(target string, attrs map[string]string, group string) *csi.NodePublishVolumeRequest {
	vc := map[string]string{
		ctxEphemeral: "true",
		ctxPodNS:     "team-a",
		ctxPodName:   "bot-1",
		ctxTokens:    `{"wag-k8s":{"token":"the-sat","expirationTimestamp":"2027-01-01T00:00:00Z"}}`,
		AttrAudience: "https://as.example",
		AttrScope:    "issues:read issues:write",
	}
	for k, v := range attrs {
		if v == "" {
			delete(vc, k)
		} else {
			vc[k] = v
		}
	}
	return &csi.NodePublishVolumeRequest{
		TargetPath:    target,
		Readonly:      true,
		VolumeContext: vc,
		VolumeCapability: &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{VolumeMountGroup: group}},
		},
	}
}

func TestPublishWritesAndRefreshes(t *testing.T) {
	d, ex, now := newDriver(t)
	target := filepath.Join(t.TempDir(), "vol")
	ctx := context.Background()

	if _, err := d.NodePublishVolume(ctx, publishReq(target, nil, "")); err != nil {
		t.Fatal(err)
	}
	if ex.calls != 1 || ex.gotSAT != "the-sat" || ex.gotAud != "https://as.example" || len(ex.gotSc) != 2 {
		t.Fatalf("exchange: %+v", ex)
	}
	path := filepath.Join(target, "token")
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if mp, _ := d.Mounter.(*mount.FakeMounter).IsLikelyNotMountPoint(target); mp {
		t.Error("target is not mounted")
	}

	// Republish before half-life: nothing to do.
	*now = t0.Add(4 * time.Minute)
	if _, err := d.NodePublishVolume(ctx, publishReq(target, nil, "")); err != nil {
		t.Fatal(err)
	}
	if ex.calls != 1 {
		t.Fatalf("refreshed too early: %d calls", ex.calls)
	}

	// Past half-life: refresh.
	*now = t0.Add(5 * time.Minute)
	if _, err := d.NodePublishVolume(ctx, publishReq(target, nil, "")); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if ex.calls != 2 || string(second) == string(first) {
		t.Fatalf("not refreshed: %d calls", ex.calls)
	}

	// Issuer down: error, old grant stays.
	*now = t0.Add(11 * time.Minute)
	ex.err = errors.New("connection refused")
	_, err = d.NodePublishVolume(ctx, publishReq(target, nil, ""))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v", err)
	}
	if kept, _ := os.ReadFile(path); string(kept) != string(second) {
		t.Error("old grant was removed")
	}
	entries, _ := os.ReadDir(target)
	if len(entries) != 1 {
		t.Errorf("leftover files: %v", entries)
	}

	if _, err := d.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{TargetPath: target}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("target still exists: %v", err)
	}
}

func TestPublishFileModeAndGroup(t *testing.T) {
	d, _, _ := newDriver(t)
	target := filepath.Join(t.TempDir(), "vol")
	gid := os.Getgid()
	if _, err := d.NodePublishVolume(context.Background(), publishReq(target, map[string]string{AttrFileName: "wag.jwt"}, strconv.Itoa(gid))); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(target, "wag.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o440 || int(fi.Sys().(*syscall.Stat_t).Gid) != gid {
		t.Errorf("mode %v gid %d", fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Gid)
	}
}

func TestPublishRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		attrs map[string]string
		ro    bool
	}{
		"no audience":       {map[string]string{AttrAudience: ""}, true},
		"not ephemeral":     {map[string]string{ctxEphemeral: ""}, true},
		"no tokens":         {map[string]string{ctxTokens: ""}, true},
		"wrong sat aud":     {map[string]string{ctxTokens: `{"api":{"token":"x"}}`}, true},
		"path in filename":  {map[string]string{AttrFileName: "../x"}, true},
		"hidden filename":   {map[string]string{AttrFileName: ".x"}, true},
		"read-write volume": {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			d, ex, _ := newDriver(t)
			req := publishReq(filepath.Join(t.TempDir(), "vol"), tc.attrs, "")
			req.Readonly = tc.ro
			_, err := d.NodePublishVolume(context.Background(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v", err)
			}
			if ex.calls != 0 {
				t.Error("exchanged despite invalid request")
			}
		})
	}
}

func TestHTTPExchanger(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("subject_token") != "sat" || r.PostForm.Get("audience") != "https://as" ||
			r.PostForm.Get("scope") != "a b" || r.PostForm.Get("requested_token_type") != wag.TokenTypeWAG {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_target","error_description":"audience is not allowed"}`)
			return
		}
		fmt.Fprintf(w, `{"access_token":"grant","issued_token_type":%q,"token_type":"N_A","expires_in":300}`, wag.TokenTypeWAG)
	}))
	defer srv.Close()
	ex, err := NewHTTPExchanger(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ex.Exchange(context.Background(), "sat", "https://as", []string{"a", "b"})
	if err != nil || got != "grant" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := ex.Exchange(context.Background(), "sat", "https://other", nil); err == nil || !strings.Contains(err.Error(), "invalid_target") {
		t.Fatalf("err = %v", err)
	}
}

func TestServeGRPC(t *testing.T) {
	d, _, _ := newDriver(t)
	sock := filepath.Join(t.TempDir(), "csi.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, "unix://"+sock, d) }()

	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	info, err := csi.NewIdentityClient(conn).GetPluginInfo(ctx, &csi.GetPluginInfoRequest{})
	if err != nil || info.Name != "wag-k8s.defakto.security" {
		t.Fatalf("plugin info: %v %v", info, err)
	}
	caps, err := csi.NewNodeClient(conn).NodeGetCapabilities(ctx, &csi.NodeGetCapabilitiesRequest{})
	if err != nil || caps.Capabilities[0].GetRpc().GetType() != csi.NodeServiceCapability_RPC_VOLUME_MOUNT_GROUP {
		t.Fatalf("capabilities: %v %v", caps, err)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("serve: %v", err)
	}
}
