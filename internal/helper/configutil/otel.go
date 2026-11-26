package configutil

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/v2/internal/version"
	"go.opentelemetry.io/otel"
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

// NewMetrics creates OTel MeterProvider. Metrics are exported via OTLP/gRPC.
func NewMetrics(ctx context.Context, res *resource.Resource, config *Telemetry) (*sdkmetric.MeterProvider, error) {
	options := []sdkmetric.Option{sdkmetric.WithResource(res)}

	if config != nil && config.OTLPEndpoint != "" {
		exporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpointURL(config.OTLPEndpoint))
		if err != nil {
			return nil, fmt.Errorf("error creating OTLP metrics exporter: %w", err)
		}

		var readerOpts []sdkmetric.PeriodicReaderOption
		if config.OTLPExportInterval > 0 {
			readerOpts = append(readerOpts, sdkmetric.WithInterval(config.OTLPExportInterval))
		}

		options = append(options, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, readerOpts...)))
	}

	provider := sdkmetric.NewMeterProvider(options...)
	otel.SetMeterProvider(provider)

	return provider, nil
}
