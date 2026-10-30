package validator

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/defakto-security/wag-k8s/internal/wag"
)

// PodMetadata adds allowlisted pod labels and annotations to the identity a
// wrapped Validator returns. It needs get on pods.
type PodMetadata struct {
	next               wag.Validator
	client             kubernetes.Interface
	labelPrefixes      []string
	annotationPrefixes []string
}

func NewPodMetadata(next wag.Validator, client kubernetes.Interface, labelPrefixes, annotationPrefixes []string) *PodMetadata {
	return &PodMetadata{next: next, client: client, labelPrefixes: labelPrefixes, annotationPrefixes: annotationPrefixes}
}

func (p *PodMetadata) Validate(ctx context.Context, token string) (*wag.Identity, error) {
	id, err := p.next.Validate(ctx, token)
	if err != nil || id.PodName == "" {
		return id, err
	}
	pod, err := p.client.CoreV1().Pods(id.Namespace).Get(ctx, id.PodName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: pod %s/%s no longer exists", wag.ErrInvalidToken, id.Namespace, id.PodName)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: get pod: %v", ErrUnavailable, err)
	}
	// A pod with the same name may have replaced the one the token is bound to.
	if string(pod.UID) != id.PodUID {
		return nil, fmt.Errorf("%w: pod %s/%s was replaced", wag.ErrInvalidToken, id.Namespace, id.PodName)
	}
	// Copy, so the cached identity is never mutated.
	out := *id
	out.PodLabels = filter(pod.Labels, p.labelPrefixes)
	out.PodAnnotations = filter(pod.Annotations, p.annotationPrefixes)
	return &out, nil
}

func filter(m map[string]string, prefixes []string) map[string]string {
	var out map[string]string
	for k, v := range m {
		for _, pre := range prefixes {
			if strings.HasPrefix(k, pre) {
				if out == nil {
					out = map[string]string{}
				}
				out[k] = v
				break
			}
		}
	}
	return out
}
