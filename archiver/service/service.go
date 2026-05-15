package service

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/base/blob-archiver/archiver/flags"
	"github.com/base/blob-archiver/archiver/metrics"
	"github.com/ethereum-optimism/optimism/op-service/httputil"
	opmetrics "github.com/ethereum-optimism/optimism/op-service/metrics"
	"github.com/ethereum/go-ethereum/log"
)

var ErrAlreadyStopped = errors.New("already stopped")

func NewService(l log.Logger, cfg flags.ArchiverConfig, api *API, archiver *Archiver, m metrics.Metricer) (*ArchiverService, error) {
	return &ArchiverService{
		log:      l,
		cfg:      cfg,
		archiver: archiver,
		metrics:  m,
		api:      api,
	}, nil
}

type ArchiverService struct {
    stopped       atomic.Bool
    log           log.Logger
    metricsServer *httputil.HTTPServer
    apiServer     *httputil.HTTPServer
    cfg           flags.ArchiverConfig
    metrics       metrics.Metricer
    api           *API
    archiver      *Archiver
}

// Start starts the archiver service. It'll start the API's as well as the archiving process.
func (a *ArchiverService) Start(ctx context.Context) error {
	if a.cfg.MetricsConfig.Enabled {
		a.log.Info("starting metrics server", "addr", a.cfg.MetricsConfig.ListenAddr, "port", a.cfg.MetricsConfig.ListenPort)
		srv, err := opmetrics.StartServer(a.metrics.Registry(), a.cfg.MetricsConfig.ListenAddr, a.cfg.MetricsConfig.ListenPort)
		if err != nil {
			return err
		}

		a.log.Info("started metrics server", "addr", srv.Addr())
		a.metricsServer = srv
	}

	srv, err := httputil.StartHTTPServer(a.cfg.ListenAddr, a.api.router)
if err != nil {
	return fmt.Errorf("failed to start Archiver API server: %w", err)
}

a.log.Info("Archiver API server started", "address", srv.Addr().String())
a.apiServer = srv

return a.archiver.Start(ctx)
}

// Stops the archiver service.
func (a *ArchiverService) Stop(ctx context.Context) error {
	if a.stopped.Load() {
		return ErrAlreadyStopped
	}
	a.log.Info("Stopping Archiver")
	a.stopped.Store(true)

	if a.apiServer != nil {
	if err := a.apiServer.Shutdown(ctx); err != nil {
		return err
	}
}

if a.metricsServer != nil {
	if err := a.metricsServer.Stop(ctx); err != nil {
		return err
	}
}

return a.archiver.Stop(ctx)
}

func (a *ArchiverService) Stopped() bool {
	return a.stopped.Load()
}
