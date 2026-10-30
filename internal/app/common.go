package app

import (
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"k8s.io/client-go/kubernetes"

	"github.com/defakto-security/wag-k8s/internal/config"
	"github.com/defakto-security/wag-k8s/internal/issuer"
	"github.com/defakto-security/wag-k8s/internal/publish"
	"github.com/defakto-security/wag-k8s/internal/wag"
)

// issuerSource returns where iss comes from, and the Ingress source when it
// needs to be checked for changes.
func issuerSource(ctx context.Context, cfg *config.Config, client kubernetes.Interface) (wag.IssuerSource, *issuer.Ingress, error) {
	if ref := cfg.Issuer.FromIngress; ref != nil {
		src, err := issuer.NewIngress(ctx, client, ref.Namespace, ref.Name)
		return src, src, err
	}
	src, err := issuer.NewStatic(cfg.Issuer.URL)
	return src, nil, err
}

// publishTargets builds the configured sinks. AWS credentials come from the
// default chain (EKS Pod Identity, IRSA, environment).
func publishTargets(ctx context.Context, cfg *config.Config) ([]publish.Target, error) {
	var targets []publish.Target
	for _, sink := range cfg.Publish.Sinks {
		if sink.S3 == nil {
			continue
		}
		var opts []func(*awsconfig.LoadOptions) error
		if sink.S3.Region != "" {
			opts = append(opts, awsconfig.WithRegion(sink.S3.Region))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("aws config: %w", err)
		}
		targets = append(targets, publish.NewS3(s3.NewFromConfig(awsCfg), sink.S3.Bucket, sink.S3.Prefix, cfg.Publish.CacheControl))
	}
	return targets, nil
}
