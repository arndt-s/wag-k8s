package validator

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/arndt-s/wag-k8s/internal/wag"
)

var now = time.Unix(1_800_000_000, 0)

func jwtWithExp(exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return "e30." + payload + ".sig"
}

type review struct {
	status authnv1.TokenReviewStatus
	err    error
	calls  int
	gotAud []string
}

func newValidator(r *review) *TokenReview {
	c := fake.NewSimpleClientset()
	c.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r.calls++
		tr := a.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		r.gotAud = tr.Spec.Audiences
		if r.err != nil {
			return true, nil, r.err
		}
		tr.Status = r.status
		return true, tr, nil
	})
	v := NewTokenReview(c, []string{"wag-k8s"}, time.Minute)
	v.now = func() time.Time { return now }
	return v
}

var okStatus = authnv1.TokenReviewStatus{
	Authenticated: true,
	Audiences:     []string{"wag-k8s"},
	User: authnv1.UserInfo{
		Username: "system:serviceaccount:team-a:bot",
		UID:      "sa-uid",
		Extra: map[string]authnv1.ExtraValue{
			"authentication.kubernetes.io/pod-name":  {"bot-123"},
			"authentication.kubernetes.io/pod-uid":   {"pod-uid"},
			"authentication.kubernetes.io/node-name": {"node-1"},
		},
	},
}

func TestValidate(t *testing.T) {
	r := &review{status: okStatus}
	v := newValidator(r)
	exp := now.Add(10 * time.Minute)
	id, err := v.Validate(context.Background(), jwtWithExp(exp))
	if err != nil {
		t.Fatal(err)
	}
	want := wag.Identity{Namespace: "team-a", ServiceAccount: "bot", ServiceAccountUID: "sa-uid", PodName: "bot-123", PodUID: "pod-uid", NodeName: "node-1", ExpiresAt: exp}
	if id.Namespace != want.Namespace || id.ServiceAccount != want.ServiceAccount || id.ServiceAccountUID != want.ServiceAccountUID ||
		id.PodName != want.PodName || id.PodUID != want.PodUID || id.NodeName != want.NodeName || !id.ExpiresAt.Equal(exp) {
		t.Errorf("identity = %+v", id)
	}
	if len(r.gotAud) != 1 || r.gotAud[0] != "wag-k8s" {
		t.Errorf("review audiences = %v", r.gotAud)
	}

	// Second call is served from cache.
	if _, err := v.Validate(context.Background(), jwtWithExp(exp)); err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 {
		t.Errorf("calls = %d, want 1", r.calls)
	}
	// Past the cache TTL, it reviews again.
	v.now = func() time.Time { return now.Add(61 * time.Second) }
	if _, err := v.Validate(context.Background(), jwtWithExp(exp)); err != nil {
		t.Fatal(err)
	}
	if r.calls != 2 {
		t.Errorf("calls = %d, want 2", r.calls)
	}
}

func TestCacheNeverOutlivesToken(t *testing.T) {
	r := &review{status: okStatus}
	v := newValidator(r)
	exp := now.Add(10 * time.Second)
	if _, err := v.Validate(context.Background(), jwtWithExp(exp)); err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now.Add(11 * time.Second) }
	if _, err := v.Validate(context.Background(), jwtWithExp(exp)); !errors.Is(err, wag.ErrInvalidToken) {
		t.Fatalf("err = %v, want expired", err)
	}
	if r.calls != 1 {
		t.Errorf("calls = %d", r.calls)
	}
}

func TestValidateRejects(t *testing.T) {
	future := jwtWithExp(now.Add(time.Hour))
	for name, tc := range map[string]struct {
		token   string
		status  authnv1.TokenReviewStatus
		err     error
		wantErr error
	}{
		"not a jwt":       {"abc", okStatus, nil, wag.ErrInvalidToken},
		"expired":         {jwtWithExp(now.Add(-time.Second)), okStatus, nil, wag.ErrInvalidToken},
		"unauthenticated": {future, authnv1.TokenReviewStatus{Error: "bad"}, nil, wag.ErrInvalidToken},
		"wrong audience": {future, func() authnv1.TokenReviewStatus {
			s := okStatus
			s.Audiences = []string{"https://kubernetes.default.svc"}
			return s
		}(), nil, wag.ErrInvalidToken},
		"not a service account": {future, func() authnv1.TokenReviewStatus {
			s := okStatus
			s.User.Username = "alice"
			return s
		}(), nil, wag.ErrInvalidToken},
		"api down": {future, okStatus, errors.New("boom"), ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			v := newValidator(&review{status: tc.status, err: tc.err})
			if _, err := v.Validate(context.Background(), tc.token); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
