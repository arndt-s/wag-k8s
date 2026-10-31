# One image for every subcommand: issuer, rotate and csi.
FROM --platform=$BUILDPLATFORM golang:1.24 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/wag-k8s ./cmd/wag-k8s

# The image runs as root because the CSI driver mounts tmpfs; the chart runs
# the issuer and rotate job as a non-root user.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/wag-k8s /usr/local/bin/wag-k8s
ENTRYPOINT ["/usr/local/bin/wag-k8s"]
