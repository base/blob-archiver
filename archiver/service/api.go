package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	m "github.com/base/blob-archiver/archiver/metrics"
	opmetrics "github.com/ethereum-optimism/optimism/op-service/metrics"
	"github.com/ethereum/go-ethereum/log"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	serverTimeout = 60 * time.Second
)

type API struct {
	router   *chi.Mux
	logger   log.Logger
	metrics  m.Metricer
	archiver *Archiver
}

// NewAPI creates a new Archiver API instance. This API exposes an admin interface to control the archiver.
func NewAPI(metrics m.Metricer, logger log.Logger, archiver *Archiver) *API {
	result := &API{
		router:   chi.NewRouter(),
		archiver: archiver,
		logger:   logger,
		metrics:  metrics,
	}

	r := result.router
	r.Use(middleware.Logger)
	r.Use(middleware.Timeout(serverTimeout))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/healthz"))

	recorder := opmetrics.NewPromHTTPRecorder(metrics.Registry(), m.MetricsNamespace)
	r.Use(func(handler http.Handler) http.Handler {
		return opmetrics.NewHTTPRecordingMiddleware(recorder, handler)
	})

	r.Get("/", http.NotFound)
	r.Post("/rearchive", result.rearchiveBlocks)

	return result
}

type rearchiveResponse struct {
	Error      string `json:"error,omitempty"`
	BlockStart uint64 `json:"blockStart"`
	BlockEnd   uint64 `json:"blockEnd"`
}

func toSlot(input string) (uint64, error) {
	if input == "" {
		return 0, fmt.Errorf("must provide param")
	}
	res, err := strconv.ParseUint(input, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid slot: \"%s\"", input)
	}
	return res, nil
}

// rearchiveBlocks rearchives blobs from blocks between the given from and to slots.
// If any blocks are already archived, they will be overwritten with data from the beacon node.
func (a *API) rearchiveBlocks(w http.ResponseWriter, r *http.Request) {
	from, err := toSlot(r.URL.Query().Get("from"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(rearchiveResponse{
			Error: fmt.Sprintf("invalid from param: %v", err),
		})
		return
	}

	to, err := toSlot(r.URL.Query().Get("to"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(rearchiveResponse{
			Error: fmt.Sprintf("invalid to param: %v", err),
		})
		return
	}

	if from > to {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(rearchiveResponse{
			Error: fmt.Sprintf("invalid range: from %d to %d", from, to),
		})
		return
	}

	blockStart, blockEnd, err := a.archiver.rearchiveRange(r.Context(), from, to)
	if err != nil {
		a.logger.Error("Failed to rearchive blocks", "err", err)

		w.WriteHeader(http.StatusInternalServerError)
		err = json.NewEncoder(w).Encode(rearchiveResponse{
			Error:      err.Error(),
			BlockStart: blockStart,
			BlockEnd:   blockEnd,
		})
	} else {
		a.logger.Info("Rearchiving blocks complete")
		w.WriteHeader(http.StatusOK)

		err = json.NewEncoder(w).Encode(rearchiveResponse{
			BlockStart: blockStart,
			BlockEnd:   blockEnd,
		})
	}

	if err != nil {
		a.logger.Error("Failed to write response", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
