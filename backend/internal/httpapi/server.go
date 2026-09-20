package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"trivy/backend/internal/config"
	"trivy/backend/internal/model"
	"trivy/backend/internal/scanner"
	"trivy/backend/internal/store"
	"trivy/backend/internal/validate"
)

type Store interface {
	Ping(context.Context) error
	Save(context.Context, string, string, model.ScanResponse) (model.ScanResponse, error)
	Get(context.Context, string) (model.ScanResponse, error)
}

type Server struct {
	cfg       config.Config
	store     Store
	scanner   *scanner.Scanner
	log       *slog.Logger
	scanSlots chan struct{}
}

func New(cfg config.Config, database Store, probes *scanner.Scanner, log *slog.Logger) *Server {
	if cfg.MaxConcurrentScans < 1 {
		cfg.MaxConcurrentScans = 1
	}
	return &Server{
		cfg: cfg, store: database, scanner: probes, log: log,
		scanSlots: make(chan struct{}, cfg.MaxConcurrentScans),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("POST /api/v1/scans", s.createScan)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.getScan)
	return s.withMiddleware(mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database is unavailable")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	var request model.ScanRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid JSON")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain one JSON value")
		return
	} else if !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body contains trailing invalid JSON")
		return
	}
	target, err := validate.Request(&request, s.cfg.MaxRequestsPerSec, s.cfg.MaxConcurrency)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	findings := append([]model.Finding{}, request.Findings...)
	var requestCoverage *model.Coverage
	if request.ScanMode == "active" || request.ScanMode == "combined" {
		if !allowedIntrusiveTarget(target, s.cfg.IntrusiveHosts) {
			writeError(w, http.StatusForbidden, "target_not_allowlisted", "active scanning is intrusive and the exact target host is not allowlisted")
			return
		}
		select {
		case s.scanSlots <- struct{}{}:
			defer func() { <-s.scanSlots }()
		default:
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusTooManyRequests, "scan_capacity_reached", "too many active scans are already running")
			return
		}
		scanCtx, cancel := context.WithTimeout(r.Context(), s.cfg.ScanTimeout)
		defer cancel()
		active, scanErr := s.scanner.Scan(scanCtx, target, *request.RateLimit, request.ExcludedPaths)
		if scanErr != nil {
			status := http.StatusBadGateway
			if errors.Is(scanErr, context.DeadlineExceeded) || errors.Is(scanErr, context.Canceled) {
				status = http.StatusGatewayTimeout
			}
			writeError(w, status, "scan_failed", scanErr.Error())
			return
		}
		findings = append(findings, active.Findings...)
		responseCoverage := active.Coverage
		requestCoverage = &responseCoverage
	}
	findings = validate.Deduplicate(findings)
	response := model.ScanResponse{Findings: findings, Summary: validate.Summary(findings), Coverage: requestCoverage}
	saved, err := s.store.Save(r.Context(), request.ScanMode, request.Target, response)
	if err != nil {
		s.log.Error("save scan", "error", err)
		writeError(w, http.StatusInternalServerError, "storage_failed", "scan could not be stored")
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func allowedIntrusiveTarget(target *url.URL, allowed []string) bool {
	host := strings.ToLower(target.Host)
	for _, candidate := range allowed {
		if strings.ToLower(strings.TrimSpace(candidate)) == host {
			return true
		}
	}
	return false
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "not_found", "scan not found")
		return
	}
	result, err := s.store.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "scan not found")
		return
	}
	if err != nil {
		s.log.Error("get scan", "error", err)
		writeError(w, http.StatusInternalServerError, "storage_failed", "scan could not be loaded")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			s.writeCORS(w, r)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.writeCORS(w, r)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Request-ID", requestID())
		next.ServeHTTP(w, r)
	})
}

func (s *Server) writeCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	for _, allowed := range s.cfg.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func requestID() string {
	value := make([]byte, 8)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return "req-" + hex.EncodeToString(value)
}
