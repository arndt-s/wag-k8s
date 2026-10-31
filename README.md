# wag-k8s
Issues Workload Authorization Grants (WAG) to Kubernetes pods, with SPIFFE IDs as the subject.

See [docs/design.md](docs/design.md) for the design.

## Install

```sh
helm install wag charts/wag-k8s -n wag-system --create-namespace \
  --set config.cluster.name=prod-eu1 \
  --set config.cluster.trustDomain=cluster.example.com \
  --set config.issuer.url=https://wag.example.com
```

See [charts/wag-k8s](charts/wag-k8s) for the values, including the CSI driver (`csi.enabled`).

## Exchanging a token

A pod projects a service account token for the `wag-k8s` audience and trades it at the issuer's token endpoint:

```sh
curl -s http://wag-k8s.wag-system.svc:8443/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode subject_token@/var/run/secrets/wag-k8s/token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:wag \
  -d audience=https://as.saas.example \
  -d scope=issues:read
```

## Development

```sh
go test ./...
test/e2e/run.sh   # kind end-to-end test; needs docker, kind, kubectl, helm
# create the first signing key (later runs rotate; schedule it as a CronJob)
go run ./cmd/wag-k8s rotate --config examples/config.yaml --kubeconfig ~/.kube/config
go run ./cmd/wag-k8s issuer --config examples/config.yaml --kubeconfig ~/.kube/config
```
