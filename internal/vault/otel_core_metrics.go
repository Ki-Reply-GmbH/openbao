package vault

import (
	"context"
	"fmt"
	"time"

	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

type coreMetrics struct {
	requestDuration otelmetric.Float64Histogram
}

func newCoreMetrics(mp otelmetric.MeterProvider) (*coreMetrics, error) {
	if mp == nil {
		mp = noop.NewMeterProvider()
	}

	meter := mp.Meter("github.com/openbao/openbao/v2/internal/vault")

	requestDuration, err := meter.Float64Histogram(
		"core.request.duration",
		otelmetric.WithDescription("Duration of core request handling."),
		otelmetric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating request duration histogram: %w", err)
	}

	return &coreMetrics{
		requestDuration: requestDuration,
	}, nil
}

func (m *coreMetrics) recordRequestDuration(ctx context.Context, startTime time.Time) {
	m.requestDuration.Record(ctx, time.Since(startTime).Seconds())
}
