// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"time"

	otelmetric "go.opentelemetry.io/otel/metric"
)

const otelMeterName = "github.com/openbao/openbao/v2/internal/vault"

var requestDurationBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
	0.25, 0.5, 1, 2.5, 5, 10, 30,
}

type coreMetrics struct {
	requestDuration otelmetric.Float64Histogram
}

func newCoreMetrics(meterProvider otelmetric.MeterProvider) (*coreMetrics, error) {
	if meterProvider == nil {
		return nil, nil
	}

	// todo: naming convention
	requestDuration, err := meterProvider.Meter(otelMeterName).Float64Histogram(
		"openbao.core.request.duration",
		otelmetric.WithDescription("Duration of core request handling."),
		otelmetric.WithUnit("s"),
		otelmetric.WithExplicitBucketBoundaries(requestDurationBuckets...),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating request duration histogram: %w", err)
	}

	return &coreMetrics{
		requestDuration: requestDuration,
	}, nil
}

func (m *coreMetrics) recordRequestDuration(ctx context.Context, startTime time.Time) {
	if m == nil {
		return
	}

	m.requestDuration.Record(ctx, time.Since(startTime).Seconds())
}
