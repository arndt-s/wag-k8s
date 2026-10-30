// Package issuer provides the iss value.
package issuer

import (
	"context"

	"github.com/arndt-s/wag-k8s/internal/config"
)

// Static is a fixed issuer URL.
type Static string

func NewStatic(url string) (Static, error) {
	if err := config.ValidateIssuerURL(url); err != nil {
		return "", err
	}
	return Static(url), nil
}

func (s Static) Issuer(context.Context) (string, error) { return string(s), nil }
