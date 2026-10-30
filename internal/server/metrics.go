package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	exchanges = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "wag_token_exchanges_total",
		Help: "Token exchange requests by outcome (issued, or the OAuth error code).",
	}, []string{"outcome"})
	exchangeDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "wag_token_exchange_duration_seconds",
		Help:    "Token exchange latency by outcome.",
		Buckets: prometheus.DefBuckets,
	}, []string{"outcome"})
)
