package keys

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/defakto-security/wag-k8s/internal/wag"
)

// SecretDataKey is the Secret data key that holds the key set as JSON.
const SecretDataKey = "keyset.json"

// SecretStore keeps the key set in one Kubernetes Secret. It needs get and
// watch on that Secret to load, and update/create to save.
type SecretStore struct {
	client    kubernetes.Interface
	namespace string
	name      string
}

func NewSecretStore(client kubernetes.Interface, namespace, name string) *SecretStore {
	return &SecretStore{client: client, namespace: namespace, name: name}
}

func (s *SecretStore) Load(ctx context.Context) (*KeySet, error) {
	sec, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("secret %s/%s: %w", s.namespace, s.name, wag.ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return decodeSecret(sec)
}

func (s *SecretStore) Save(ctx context.Context, ks *KeySet, version string) error {
	b, err := json.Marshal(ks)
	if err != nil {
		return err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       s.namespace,
			Name:            s.name,
			ResourceVersion: version,
			Labels:          map[string]string{"app.kubernetes.io/managed-by": "wag-k8s"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{SecretDataKey: b},
	}
	if version == "" {
		_, err = s.client.CoreV1().Secrets(s.namespace).Create(ctx, sec, metav1.CreateOptions{})
	} else {
		_, err = s.client.CoreV1().Secrets(s.namespace).Update(ctx, sec, metav1.UpdateOptions{})
	}
	if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("secret %s/%s: %w", s.namespace, s.name, wag.ErrConflict)
	}
	return err
}

// Watch follows the Secret with get + watch only, so RBAC can limit the
// issuer to this one Secret by resourceNames.
func (s *SecretStore) Watch(ctx context.Context, fn func(*KeySet)) error {
	backoff := time.Second
	for ctx.Err() == nil {
		rv, err := s.loadAndNotify(ctx, fn)
		if err == nil {
			err = s.watchFrom(ctx, rv, fn)
		}
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			slog.Warn("watching signing key secret", "namespace", s.namespace, "name", s.name, "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
	}
	return ctx.Err()
}

func (s *SecretStore) loadAndNotify(ctx context.Context, fn func(*KeySet)) (string, error) {
	sec, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Watch from scratch; the bootstrap job will create it.
		return "", nil
	}
	if err != nil {
		return "", err
	}
	ks, err := decodeSecret(sec)
	if err != nil {
		slog.Error("signing key secret is invalid", "err", err)
	} else {
		fn(ks)
	}
	return sec.ResourceVersion, nil
}

func (s *SecretStore) watchFrom(ctx context.Context, rv string, fn func(*KeySet)) error {
	w, err := s.client.CoreV1().Secrets(s.namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector:   fields.OneTermEqualSelector("metadata.name", s.name).String(),
		ResourceVersion: rv,
	})
	if err != nil {
		return err
	}
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.ResultChan():
			if !ok {
				return nil // channel closed: reload and watch again
			}
			switch ev.Type {
			case watch.Added, watch.Modified:
				sec, ok := ev.Object.(*corev1.Secret)
				if !ok {
					continue
				}
				ks, err := decodeSecret(sec)
				if err != nil {
					slog.Error("signing key secret is invalid", "err", err)
					continue
				}
				fn(ks)
			case watch.Deleted:
				// Keep signing with what we have; a deleted Secret is an
				// operator error and rotation will recreate it.
				slog.Error("signing key secret was deleted", "namespace", s.namespace, "name", s.name)
			case watch.Error:
				return fmt.Errorf("watch error: %v", apierrors.FromObject(ev.Object))
			}
		}
	}
}

func decodeSecret(sec *corev1.Secret) (*KeySet, error) {
	b, ok := sec.Data[SecretDataKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no %q", sec.Namespace, sec.Name, SecretDataKey)
	}
	var ks KeySet
	if err := json.Unmarshal(b, &ks); err != nil {
		return nil, fmt.Errorf("secret %s/%s: %w", sec.Namespace, sec.Name, err)
	}
	ks.Version = sec.ResourceVersion
	return &ks, nil
}
