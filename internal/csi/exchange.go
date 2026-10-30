package csi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/defakto-security/wag-k8s/internal/wag"
)

// Exchanger trades a service account token for a grant.
type Exchanger interface {
	Exchange(ctx context.Context, sat, audience string, scopes []string) (string, error)
}

// HTTPExchanger calls the issuer's token endpoint.
type HTTPExchanger struct {
	Endpoint string
	Client   *http.Client
}

// NewHTTPExchanger trusts caFile in addition to the system roots when set.
func NewHTTPExchanger(endpoint, caFile string) (*HTTPExchanger, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &HTTPExchanger{Endpoint: endpoint, Client: &http.Client{Transport: tr, Timeout: 15 * time.Second}}, nil
}

func (e *HTTPExchanger) Exchange(ctx context.Context, sat, audience string, scopes []string) (string, error) {
	form := url.Values{
		"grant_type":           {wag.GrantTypeTokenExchange},
		"subject_token":        {sat},
		"subject_token_type":   {wag.TokenTypeJWT},
		"requested_token_type": {wag.TokenTypeWAG},
		"audience":             {audience},
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		var oe struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oe)
		if oe.Error == "" {
			return "", fmt.Errorf("token endpoint returned %s", resp.Status)
		}
		return "", fmt.Errorf("token endpoint returned %s: %s: %s", resp.Status, oe.Error, oe.Description)
	}
	var tr struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("token endpoint response: %w", err)
	}
	if tr.AccessToken == "" || tr.IssuedTokenType != wag.TokenTypeWAG {
		return "", errors.New("token endpoint response has no grant")
	}
	return tr.AccessToken, nil
}
