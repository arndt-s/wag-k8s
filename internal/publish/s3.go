// Package publish puts issuer metadata and JWKS where authorization servers
// fetch them, and merges one JWKS across clusters in shared mode.
package publish

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/defakto-security/wag-k8s/internal/wag"
)

// S3API is the part of the S3 client the publisher uses.
type S3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3 publishes to one bucket under an optional prefix, using S3 conditional
// writes for compare-and-swap.
type S3 struct {
	client       S3API
	bucket       string
	prefix       string
	cacheControl string
}

func NewS3(client S3API, bucket, prefix, cacheControl string) *S3 {
	return &S3{client: client, bucket: bucket, prefix: prefix, cacheControl: cacheControl}
}

func (p *S3) String() string { return "s3://" + path.Join(p.bucket, p.prefix) }

func (p *S3) key(docPath string) string {
	// Document paths start with "/"; S3 keys don't.
	return strings.TrimPrefix(path.Join(p.prefix, docPath), "/")
}

func (p *S3) Get(ctx context.Context, docPath string) ([]byte, string, error) {
	out, err := p.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(p.bucket),
		Key:    aws.String(p.key(docPath)),
	})
	if err != nil {
		if httpStatus(err) == http.StatusNotFound {
			return nil, "", fmt.Errorf("%s%s: %w", p, docPath, wag.ErrNotFound)
		}
		return nil, "", err
	}
	defer out.Body.Close()
	b, err := io.ReadAll(io.LimitReader(out.Body, maxDocumentBytes))
	if err != nil {
		return nil, "", err
	}
	return b, aws.ToString(out.ETag), nil
}

func (p *S3) Put(ctx context.Context, docPath, contentType string, body io.Reader, cond wag.Condition) error {
	in := &s3.PutObjectInput{
		Bucket:      aws.String(p.bucket),
		Key:         aws.String(p.key(docPath)),
		Body:        body,
		ContentType: aws.String(contentType),
	}
	if p.cacheControl != "" {
		in.CacheControl = aws.String(p.cacheControl)
	}
	if cond.IfMatch != "" {
		in.IfMatch = aws.String(cond.IfMatch)
	}
	if cond.IfNoneMatch {
		in.IfNoneMatch = aws.String("*")
	}
	_, err := p.client.PutObject(ctx, in)
	if s := httpStatus(err); s == http.StatusPreconditionFailed || s == http.StatusConflict {
		// 409 is S3's ConditionalRequestConflict: a concurrent write won.
		return fmt.Errorf("%s%s: %w", p, docPath, wag.ErrConflict)
	}
	return err
}

func httpStatus(err error) int {
	if err == nil {
		return 0
	}
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	var ae smithy.APIError
	if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchKey" {
		return http.StatusNotFound
	}
	return -1
}
