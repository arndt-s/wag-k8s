# wag-k8s Helm chart

Installs the wag-k8s issuer (Deployment), the key rotation CronJob, a
pre-install hook that creates the first signing key, and optionally the CSI
node plugin.

```sh
helm install wag charts/wag-k8s -n wag-system --create-namespace \
  --set config.cluster.name=prod-eu1 \
  --set config.cluster.trustDomain=cluster.example.com \
  --set config.issuer.url=https://wag.example.com
```

`config` is the issuer's config file (see `examples/config.yaml`); the chart
fills in the key Secret, the in-cluster token endpoint and token TLS. Set
`ingress.enabled` to expose metadata and JWKS, `csi.enabled` to install the
CSI driver, and `rotation.serviceAccount.annotations` to give the rotation job
cloud credentials for publishing to S3.
