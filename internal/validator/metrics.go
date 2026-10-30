package validator

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var cacheHits = promauto.NewCounter(prometheus.CounterOpts{
	Name: "wag_tokenreview_cache_hits_total",
	Help: "Token exchanges served from the TokenReview cache.",
})
