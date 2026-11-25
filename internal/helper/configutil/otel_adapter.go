package configutil

import (
	"context"

	metrics "github.com/armon/go-metrics"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter                                         = otel.Meter("github.com/hashicorp/raft")
	raftApplyCounter, txnFastApplyReadMissCounter metric.Float64Counter
)

func init() {
	var err error
	raftApplyCounter, err = meter.Float64Counter(
		"apply",
		metric.WithDescription("Number of raft applies"),
		metric.WithUnit("{count}"), // TODO: find unit
	)
	if err != nil {
		panic(err)
	}
}

type OTLAdapter struct{}

// AddSample implements metrics.MetricSink.
func (o OTLAdapter) AddSample(key []string, val float32) {
}

// AddSampleWithLabels implements metrics.MetricSink.
func (o OTLAdapter) AddSampleWithLabels(key []string, val float32, labels []metrics.Label) {
}

// EmitKey implements metrics.MetricSink.
func (o OTLAdapter) EmitKey(key []string, val float32) {
}

// IncrCounter implements metrics.MetricSink.
func (o OTLAdapter) IncrCounter(key []string, val float32) {
	o.IncrCounterWithLabels(key, val, nil)
}

// IncrCounterWithLabels implements metrics.MetricSink.
func (o OTLAdapter) IncrCounterWithLabels(key []string, val float32, labels []metrics.Label) {
	if len(key) < 3 || key[1] != "raft" || key[0] != "vault" {
		return
	}

	if key[2] == "apply" {
		if len(labels) > 0 {
			attributes := make([]attribute.KeyValue, 0, len(labels))
			for _, label := range labels {
				attributes = append(attributes, attribute.String(label.Name, label.Value))
			}
			metric.WithAttributeSet(attribute.NewSet(attributes...))
		} else {
			raftApplyCounter.Add(context.Background(), float64(val))
		}
	}
}

// SetGauge implements metrics.MetricSink.
func (o OTLAdapter) SetGauge(key []string, val float32) {
}

// SetGaugeWithLabels implements metrics.MetricSink.
func (o OTLAdapter) SetGaugeWithLabels(key []string, val float32, labels []metrics.Label) {
}
