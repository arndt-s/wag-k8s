package issuer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/defakto-security/wag-k8s/internal/config"
)

const (
	// HostAnnotation picks the issuer host when the Ingress has several.
	HostAnnotation = "wag-k8s.io/issuer-host"
	// PathAnnotation adds a path to the issuer URL, e.g. "/tenant-a".
	PathAnnotation = "wag-k8s.io/issuer-path"
)

// Ingress derives iss from an Ingress once, at startup. Changing iss breaks
// every authorization server that trusts it, so a later change to the Ingress
// is reported loudly and never applied.
type Ingress struct {
	client    kubernetes.Interface
	namespace string
	name      string
	url       string
}

func NewIngress(ctx context.Context, client kubernetes.Interface, namespace, name string) (*Ingress, error) {
	i := &Ingress{client: client, namespace: namespace, name: name}
	u, err := i.derive(ctx)
	if err != nil {
		return nil, err
	}
	i.url = u
	slog.Info("issuer derived from ingress", "ingress", namespace+"/"+name, "issuer", u)
	return i, nil
}

func (i *Ingress) Issuer(context.Context) (string, error) { return i.url, nil }

// Check re-reads the Ingress every interval until ctx is done and logs an
// error whenever it no longer yields the issuer in use.
func (i *Ingress) Check(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		u, err := i.derive(ctx)
		switch {
		case err != nil:
			slog.Error("issuer ingress is no longer usable; still issuing with the original issuer", "issuer", i.url, "err", err)
		case u != i.url:
			slog.Error("issuer ingress changed; still issuing with the original issuer, restart to switch (this breaks every authorization server registration)", "issuer", i.url, "ingressIssuer", u)
		}
	}
}

func (i *Ingress) derive(ctx context.Context) (string, error) {
	ing, err := i.client.NetworkingV1().Ingresses(i.namespace).Get(ctx, i.name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("issuer ingress %s/%s: %w", i.namespace, i.name, err)
	}
	return FromIngress(ing)
}

// FromIngress builds https://<host>[<path>] from an Ingress. The host must be
// covered by the Ingress's TLS section.
func FromIngress(ing *networkingv1.Ingress) (string, error) {
	var hosts []string
	for _, r := range ing.Spec.Rules {
		if r.Host != "" && !slices.Contains(hosts, r.Host) {
			hosts = append(hosts, r.Host)
		}
	}
	host := ing.Annotations[HostAnnotation]
	switch {
	case host != "":
		if !slices.Contains(hosts, host) {
			return "", fmt.Errorf("annotation %s=%q names no rule host of the ingress", HostAnnotation, host)
		}
	case len(hosts) == 1:
		host = hosts[0]
	case len(hosts) == 0:
		return "", errors.New("ingress has no rule with a host")
	default:
		return "", fmt.Errorf("ingress has several hosts %v; pick one with the %s annotation", hosts, HostAnnotation)
	}
	if strings.HasPrefix(host, "*") {
		return "", fmt.Errorf("issuer host %q must not be a wildcard", host)
	}
	if !tlsCovers(ing.Spec.TLS, host) {
		return "", fmt.Errorf("ingress host %q is not listed under spec.tls; the issuer must be served over https", host)
	}
	path := ing.Annotations[PathAnnotation]
	if path != "" && !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("annotation %s must start with '/'", PathAnnotation)
	}
	u := "https://" + host + path
	if err := config.ValidateIssuerURL(u); err != nil {
		return "", err
	}
	return u, nil
}

func tlsCovers(tls []networkingv1.IngressTLS, host string) bool {
	for _, t := range tls {
		for _, h := range t.Hosts {
			if h == host {
				return true
			}
			if suffix, ok := strings.CutPrefix(h, "*"); ok && strings.HasSuffix(host, suffix) &&
				!strings.Contains(strings.TrimSuffix(host, suffix), ".") {
				return true
			}
		}
	}
	return false
}
