package monitoring

import (
	"context"
	"errors"
	"sync"

	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/prometheus/client_golang/prometheus"
)

// reorgCollector exports the re-org watcher's registry: what the
// daemon has staked on chain outcomes and how far site delivery lags
// sensed chain truth.
type reorgCollector struct {
	collectMx sync.Mutex

	cfg      *PrometheusConfig
	registry *prometheus.Registry

	liveAnchorings *prometheus.GaugeVec
	stuckDelivery  prometheus.Gauge
	deliveryLag    prometheus.Gauge
}

func newReorgCollector(cfg *PrometheusConfig,
	registry *prometheus.Registry) (*reorgCollector, error) {

	if cfg == nil {
		return nil, errors.New("reorg collector prometheus cfg is " +
			"nil")
	}
	if cfg.AnchoringRegistry == nil {
		return nil, errors.New("reorg collector anchoring registry " +
			"is nil")
	}

	return &reorgCollector{
		cfg:      cfg,
		registry: registry,
		liveAnchorings: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "reorg_live_anchorings",
				Help: "Live speculative anchorings by " +
					"site and sensed phase",
			},
			[]string{"site", "phase"},
		),
		stuckDelivery: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "reorg_stuck_deliveries",
				Help: "Anchorings whose site delivery is " +
					"flagged stuck",
			},
		),
		deliveryLag: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "reorg_delivery_lag",
				Help: "Anchorings whose delivered phase " +
					"lags the sensed phase",
			},
		),
	}, nil
}

// Describe sends the super-set of all possible descriptors of metrics
// collected by this Collector to the provided channel.
//
// NOTE: Part of the prometheus.Collector interface.
func (c *reorgCollector) Describe(ch chan<- *prometheus.Desc) {
	c.collectMx.Lock()
	defer c.collectMx.Unlock()

	c.liveAnchorings.Describe(ch)
	c.stuckDelivery.Describe(ch)
	c.deliveryLag.Describe(ch)
}

// Collect is called by the Prometheus registry when collecting
// metrics.
//
// NOTE: Part of the prometheus.Collector interface.
func (c *reorgCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectMx.Lock()
	defer c.collectMx.Unlock()

	ctxt, cancel := context.WithTimeout(
		context.Background(), c.cfg.CollectorRPCTimeout,
	)
	defer cancel()

	live, err := c.cfg.AnchoringRegistry.LiveAnchorings(ctxt)
	if err != nil {
		log.Errorf("unable to list live anchorings: %v", err)
		return
	}

	c.liveAnchorings.Reset()

	var stuck, lagging float64
	for _, anchoring := range live {
		kind := tapreorg.CodeOf(anchoring.Phase)
		c.liveAnchorings.WithLabelValues(
			string(anchoring.Site), phaseName(kind),
		).Inc()

		if anchoring.Stuck {
			stuck++
		}
		if !tapreorg.PhaseEqual(
			anchoring.Phase, anchoring.DeliveredPhase,
		) {

			lagging++
		}
	}

	c.stuckDelivery.Set(stuck)
	c.deliveryLag.Set(lagging)

	c.liveAnchorings.Collect(ch)
	c.stuckDelivery.Collect(ch)
	c.deliveryLag.Collect(ch)
}

// phaseName renders a phase code as a stable label value.
func phaseName(code tapreorg.PhaseCode) string {
	switch code {
	case tapreorg.PhaseCodeUnwitnessed:
		return "unwitnessed"
	case tapreorg.PhaseCodeWitnessed:
		return "witnessed"
	case tapreorg.PhaseCodeConflicted:
		return "conflicted"
	case tapreorg.PhaseCodeBuried:
		return "buried"
	case tapreorg.PhaseCodeAbandoned:
		return "abandoned"
	case tapreorg.PhaseCodeWithdrawn:
		return "withdrawn"
	default:
		return "unknown"
	}
}
