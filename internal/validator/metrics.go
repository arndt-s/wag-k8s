package validator

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var cacheHits = func() metric.Int64Counter {
	c, err := otel.Meter("github.com/defakto-security/wag-k8s/internal/validator").Int64Counter("wag.tokenreview.cache_hits",
		metric.WithDescription("Token exchanges served from the TokenReview cache."),
		metric.WithUnit("{request}"))
	if err != nil {
		panic(err)
	}
	return c
}()
