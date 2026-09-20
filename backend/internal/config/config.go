package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Address             string
	DatabaseURL         string
	AllowedOrigins      []string
	AllowPrivateTargets bool
	IntrusiveHosts      []string
	ScanTimeout         time.Duration
	RequestTimeout      time.Duration
	MaxResponseBytes    int64
	MaxRequestBytes     int64
	MaxRequestsPerSec   int
	MaxConcurrency      int
	MaxScanPages        int
	MaxScanDepth        int
	MaxScanRequests     int
	MaxConcurrentScans  int
	Retention           time.Duration
	CleanupInterval     time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Address:             env("TRIVY_ADDRESS", ":8080"),
		DatabaseURL:         os.Getenv("TRIVY_DATABASE_URL"),
		AllowedOrigins:      splitCSV(env("TRIVY_ALLOWED_ORIGINS", "http://localhost:5173")),
		AllowPrivateTargets: envBool("TRIVY_ALLOW_PRIVATE_TARGETS", false),
		IntrusiveHosts:      splitCSV(os.Getenv("TRIVY_INTRUSIVE_ALLOWED_HOSTS")),
		ScanTimeout:         envDuration("TRIVY_SCAN_TIMEOUT", 60*time.Second),
		RequestTimeout:      envDuration("TRIVY_REQUEST_TIMEOUT", 8*time.Second),
		MaxResponseBytes:    envInt64("TRIVY_MAX_RESPONSE_BYTES", 2<<20),
		MaxRequestBytes:     envInt64("TRIVY_MAX_REQUEST_BYTES", 1<<20),
		MaxRequestsPerSec:   envInt("TRIVY_MAX_REQUESTS_PER_SECOND", 10),
		MaxConcurrency:      envInt("TRIVY_MAX_CONCURRENCY", 5),
		MaxScanPages:        envInt("TRIVY_MAX_SCAN_PAGES", 25),
		MaxScanDepth:        envInt("TRIVY_MAX_SCAN_DEPTH", 2),
		MaxScanRequests:     envInt("TRIVY_MAX_SCAN_REQUESTS", 100),
		MaxConcurrentScans:  envInt("TRIVY_MAX_CONCURRENT_SCANS", 2),
		Retention:           envDuration("TRIVY_RETENTION", 7*24*time.Hour),
		CleanupInterval:     envDuration("TRIVY_CLEANUP_INTERVAL", time.Hour),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("TRIVY_DATABASE_URL is required")
	}
	if cfg.ScanTimeout <= 0 || cfg.RequestTimeout <= 0 || cfg.MaxResponseBytes <= 0 || cfg.MaxRequestBytes <= 0 {
		return Config{}, fmt.Errorf("timeouts and byte limits must be positive")
	}
	if cfg.MaxRequestsPerSec < 1 || cfg.MaxConcurrency < 1 || cfg.MaxScanPages < 1 || cfg.MaxScanDepth < 0 || cfg.MaxScanRequests < 1 || cfg.MaxConcurrentScans < 1 || cfg.Retention <= 0 || cfg.CleanupInterval <= 0 {
		return Config{}, fmt.Errorf("scanner limits, retention, and cleanup interval must be positive")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return value
}

func envInt64(key string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil {
		return fallback
	}
	return value
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func splitCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
