package server

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter     = otel.Meter("github.com/defakto-security/wag-k8s/internal/server")
	exchanges = must(meter.Int64Counter("wag.token_exchanges",
		metric.WithDescription("Token exchange requests by outcome (issued, or the OAuth error code)."),
		metric.WithUnit("{request}")))
	exchangeDuration = must(meter.Float64Histogram("wag.token_exchange.duration",
		metric.WithDescription("Token exchange latency by outcome."),
		metric.WithUnit("s")))
)

func recordExchange(ctx context.Context, outcome string, start time.Time) {
	attrs := metric.WithAttributes(attribute.String("outcome", outcome))
	exchanges.Add(ctx, 1, attrs)
	exchangeDuration.Record(ctx, time.Since(start).Seconds(), attrs)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
