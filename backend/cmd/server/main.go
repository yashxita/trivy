package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"trivy/backend/internal/config"
	"trivy/backend/internal/httpapi"
	"trivy/backend/internal/scanner"
	"trivy/backend/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	database, err := store.Open(ctx, cfg.DatabaseURL, cfg.Retention)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	probes := scanner.New(scanner.Config{
		AllowPrivateTargets: cfg.AllowPrivateTargets,
		RequestTimeout:      cfg.RequestTimeout,
		MaxResponseBytes:    cfg.MaxResponseBytes,
		UserAgent:           "Trivy-Scanner/1.0 (+local security audit)",
		MaxPages:            cfg.MaxScanPages,
		MaxDepth:            cfg.MaxScanDepth,
		MaxRequests:         cfg.MaxScanRequests,
	})
	api := httpapi.New(cfg, database, probes, logger)
	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           api.Handler(),
		ReadHeaderTimeout: cfg.RequestTimeout,
		ReadTimeout:       cfg.RequestTimeout,
		WriteTimeout:      cfg.ScanTimeout + cfg.RequestTimeout,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := database.DeleteExpired(ctx); err != nil {
					logger.Error("delete expired scans", "error", err)
				}
			}
		}
	}()

	go func() {
		logger.Info("server listening", "address", cfg.Address)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown", "error", err)
	}
}
