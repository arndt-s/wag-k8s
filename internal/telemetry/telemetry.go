// Package telemetry sets up OpenTelemetry metrics.
package telemetry

import (
	"context"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Setup installs the global meter provider. The exporter follows the standard
// OTEL_METRICS_EXPORTER and OTEL_EXPORTER_OTLP_* variables; when they are not
// set, metrics are exposed in Prometheus format on the admin listener's
// /metrics. The returned function flushes and stops the exporter.
func Setup(ctx context.Context, version string) (func(context.Context) error, error) {
	reader, err := autoexport.NewMetricReader(ctx, autoexport.WithFallbackMetricReader(
		func(context.Context) (sdkmetric.Reader, error) { return prometheus.New() },
	))
	if err != nil {
		return nil, err
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("wag-k8s"),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res))
	otel.SetMeterProvider(mp)
	return mp.Shutdown, nil
}
