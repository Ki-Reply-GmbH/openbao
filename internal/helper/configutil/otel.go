package configutil

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

const (
	serviceName    = "openbao"
	serviceVersion = ""

	envOTLPEndpoint        = "OTEL_EXPORTER_OTLP_ENDPOINT"
	envOTLPMetricsEndpoint = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
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
			semconv.ServiceVersion(serviceVersion),
			semconv.ServiceInstanceID(instanceID),
		),
	)
}

func NewMetrics(ctx context.Context, res *resource.Resource) (*sdkmetric.MeterProvider, error) {
	options := []sdkmetric.Option{sdkmetric.WithResource(res)}

	metricsEndpoint := strings.TrimSpace(os.Getenv(envOTLPMetricsEndpoint))
	commonEndpoint := strings.TrimSpace(os.Getenv(envOTLPEndpoint))

	if metricsEndpoint != "" || commonEndpoint != "" {
		exporter, err := otlpmetrichttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("create OTLP metrics exporter: %w", err)
		}

		reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(5*time.Second))

		options = append(options, sdkmetric.WithReader(reader))
	}

	provider := sdkmetric.NewMeterProvider(options...)
	otel.SetMeterProvider(provider)

	return provider, nil
}
