# Installing and publishing

## Releases

CI publishes to the GitHub Container Registry of the repository it runs in:

| Trigger      | Image                                          | Chart                                                  |
|--------------|------------------------------------------------|--------------------------------------------------------|
| push to main | `ghcr.io/<owner>/wag-k8s:edge`, `:sha-<commit>` | none                                                   |
| tag `vX.Y.Z` | `ghcr.io/<owner>/wag-k8s:X.Y.Z`, `:X.Y`         | `oci://ghcr.io/<owner>/charts/wag-k8s`, version `X.Y.Z` |

Images are built for linux/amd64 and linux/arm64. A tag also creates a
GitHub release with the packaged chart attached. A tag with a suffix such as
`v0.2.0-rc.1` is marked as a pre-release.

To cut a release, push a tag from main, or create the release in the GitHub
UI with a new tag. The chart is attached to that release either way:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

Tags must be full semver (`v0.1.0`, not `v0.1`). CI rejects other tags
before publishing anything.

The version in `Chart.yaml` is a placeholder. The release sets the chart
version and appVersion from the tag, and points `image.repository` at the
image pushed by the same run.

GHCR creates new packages as private. After the first release, make both
`wag-k8s` and `charts/wag-k8s` public under the owner's Packages settings, or
give clusters an `imagePullSecrets` entry.

## Installing

```sh
helm install wag oci://ghcr.io/<owner>/charts/wag-k8s --version 0.1.0 \
  -n wag-system --create-namespace -f values.yaml
```

`values.yaml` holds the issuer config under `config` (see
[examples/config.yaml](../examples/config.yaml) for every field):

```yaml
config:
  cluster:
    name: prod-eu1
    trustDomain: cluster.example.com
  issuer:
    url: https://wag.example.com
  policy:
    rules:
      - namespaces:
          - team-a
        audiences:
          - https://as.saas.example
```

No workload gets a grant until a policy rule allows it.

The issuer URL must be reachable over HTTPS by whoever verifies grants. There
are two ways to serve the metadata and JWKS:

- **From the issuer itself** (`publish.serve: true`, the default): set
  `ingress.enabled`, `ingress.host` and `ingress.tls`. The Ingress exposes only
  the public listener. The token endpoint stays in-cluster.
- **From S3** (required for shared mode, where several clusters share one
  issuer): the rotate job writes the documents to a bucket, and a CDN serves
  them. The rest of this page covers that setup.

## Publishing to S3

### Objects

For issuer `https://wag.example.com/<path>` and sink prefix `<prefix>`, the
rotate job writes:

- `<prefix>/.well-known/oauth-authorization-server<path>`: the metadata
- `<prefix><path>/jwks.json`: the JWKS

Both are written with `Content-Type: application/json` and the
`publish.cacheControl` header (default `public, max-age=300`). Writes use S3
conditional requests (`If-Match` / `If-None-Match`), so several clusters can
update a shared JWKS safely.

### Serving over HTTPS

S3 website endpoints are plain HTTP, so put a CDN in front of the bucket. With
CloudFront:

1. Keep the bucket private, with Block Public Access on.
2. Create a distribution with the bucket as origin, using Origin Access
   Control, and the issuer's host as alternate domain name with an ACM
   certificate (in us-east-1).
3. If you use a prefix, set it as the origin path, so the issuer path maps
   onto the objects above.
4. Allow the distribution to read the bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-wag-issuer/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::111122223333:distribution/EDFDVBD6EXAMPLE"
        }
      }
    }
  ]
}
```

CloudFront honours the `Cache-Control` header that the rotate job sets.

### Permissions for the rotate job

Only the rotate CronJob writes to S3. The issuer and the first-key hook never
do. Its role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::my-wag-issuer/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-wag-issuer"
    }
  ]
}
```

`s3:ListBucket` matters. Without it, S3 answers 403 instead of 404 for an
object that does not exist yet, and the first publish fails. Narrow both
resources to your prefix if the bucket holds other data.

The rotate job's service account is `<release>-wag-k8s-rotate` (or
`<release>-rotate` when the release name contains `wag-k8s`). The job uses the
AWS SDK's default credential chain, so any of these work:

- **IRSA**: give the role a trust policy for
  `system:serviceaccount:wag-system:wag-wag-k8s-rotate`, and set
  `rotation.serviceAccount.annotations` to
  `eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/wag-rotate`.
- **EKS Pod Identity**: create a pod identity association for that service
  account. No annotations are needed.

Then add the sink to the config:

```yaml
config:
  publish:
    sinks:
      - s3:
          bucket: my-wag-issuer
          prefix: ""
          region: eu-central-1
```

### Shared mode

To have several clusters behind one issuer, install the chart in each cluster
with the same `issuer.url` and sink, a distinct `cluster.name`, and:

```yaml
config:
  publish:
    mode: shared
    serve: false
```

Give every cluster's rotate role the permissions above. Each cluster signs
with its own key and merges only its own keys into the shared JWKS. The
metadata document is written once and has no `token_endpoint`, because that
differs per cluster.
