package issuer

import (
	"context"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func ingress(annotations map[string]string, tlsHosts []string, hosts ...string) *networkingv1.Ingress {
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "wag-system", Name: "wag", Annotations: annotations}}
	for _, h := range hosts {
		ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{Host: h})
	}
	if tlsHosts != nil {
		ing.Spec.TLS = []networkingv1.IngressTLS{{Hosts: tlsHosts}}
	}
	return ing
}

func TestFromIngress(t *testing.T) {
	for name, tc := range map[string]struct {
		ing     *networkingv1.Ingress
		want    string
		wantErr string
	}{
		"single host":     {ingress(nil, []string{"wag.example.com"}, "wag.example.com"), "https://wag.example.com", ""},
		"wildcard tls":    {ingress(nil, []string{"*.example.com"}, "wag.example.com"), "https://wag.example.com", ""},
		"with path":       {ingress(map[string]string{PathAnnotation: "/tenant-a"}, []string{"wag.example.com"}, "wag.example.com"), "https://wag.example.com/tenant-a", ""},
		"picked host":     {ingress(map[string]string{HostAnnotation: "b.example.com"}, []string{"a.example.com", "b.example.com"}, "a.example.com", "b.example.com"), "https://b.example.com", ""},
		"no tls":          {ingress(nil, nil, "wag.example.com"), "", "spec.tls"},
		"tls other host":  {ingress(nil, []string{"other.example.com"}, "wag.example.com"), "", "spec.tls"},
		"wildcard 2 deep": {ingress(nil, []string{"*.example.com"}, "a.b.example.com"), "", "spec.tls"},
		"several hosts":   {ingress(nil, []string{"a", "b"}, "a", "b"), "", "several hosts"},
		"no host":         {ingress(nil, nil), "", "no rule"},
		"unknown pick":    {ingress(map[string]string{HostAnnotation: "c"}, []string{"a"}, "a"), "", "names no rule"},
		"bad path":        {ingress(map[string]string{PathAnnotation: "x"}, []string{"a.example.com"}, "a.example.com"), "", "start with"},
		"trailing slash":  {ingress(map[string]string{PathAnnotation: "/x/"}, []string{"a.example.com"}, "a.example.com"), "", "must not end"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := FromIngress(tc.ing)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestNewIngress(t *testing.T) {
	c := fake.NewSimpleClientset(ingress(nil, []string{"wag.example.com"}, "wag.example.com"))
	src, err := NewIngress(context.Background(), c, "wag-system", "wag")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := src.Issuer(context.Background()); got != "https://wag.example.com" {
		t.Errorf("issuer = %q", got)
	}
	if _, err := NewIngress(context.Background(), c, "wag-system", "missing"); err == nil {
		t.Error("expected error for missing ingress")
	}
}
