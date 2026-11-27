package configutil

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/v2/internal/version"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

const (
	serviceName = "openbao"
)

func NewOTelResource(ctx context.Context) (*resource.Resource, error) {
	instanceID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("error generating service instance ID: %w", err)
	}

	return resource.New(
		ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version.GetVersion().VersionNumber()),
			semconv.ServiceInstanceID(instanceID),
		),
	)
}

// NewMeterProvider creates an OTLP/gRPC metrics pipeline.
func NewMeterProvider(ctx context.Context, res *resource.Resource, endpoint string, exportInterval time.Duration) (*sdkmetric.MeterProvider, error) {
	exporter, err := otlpmetricgrpc.New(
		ctx,
		otlpmetricgrpc.WithEndpointURL(endpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP metrics exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(
		exporter,
		sdkmetric.WithInterval(exportInterval),
	)

	return sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	), nil
}
