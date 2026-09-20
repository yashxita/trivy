package store

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trivy/backend/internal/model"
)

//go:embed migrations/*.sql
var migrations embed.FS

var ErrNotFound = errors.New("scan not found")

type Postgres struct {
	pool      *pgxpool.Pool
	retention time.Duration
}

func Open(ctx context.Context, databaseURL string, retention time.Duration) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	store := &Postgres{pool: pool, retention: retention}
	if err := store.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *Postgres) Close() { s.pool.Close() }

func (s *Postgres) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Postgres) Migrate(ctx context.Context) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		migration, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, string(migration)); err != nil {
			return fmt.Errorf("migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func (s *Postgres) Save(ctx context.Context, mode, target string, response model.ScanResponse) (model.ScanResponse, error) {
	id, err := newUUID()
	if err != nil {
		return model.ScanResponse{}, err
	}
	response.ScanID = id
	sanitized := SanitizeResponse(response)
	findings, err := json.Marshal(sanitized.Findings)
	if err != nil {
		return model.ScanResponse{}, err
	}
	summary, err := json.Marshal(sanitized.Summary)
	if err != nil {
		return model.ScanResponse{}, err
	}
	coverage, err := json.Marshal(sanitized.Coverage)
	if err != nil {
		return model.ScanResponse{}, err
	}
	expiresAt := time.Now().UTC().Add(s.retention)
	_, err = s.pool.Exec(ctx, `
		INSERT INTO scans (id, scan_mode, target, findings, summary, coverage, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, mode, RedactURL(target), findings, summary, coverage, expiresAt,
	)
	if err != nil {
		return model.ScanResponse{}, err
	}
	return response, nil
}

func (s *Postgres) Get(ctx context.Context, id string) (model.ScanResponse, error) {
	var findingsJSON, summaryJSON, coverageJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT findings, summary, COALESCE(coverage, 'null'::jsonb) FROM scans
		WHERE id = $1 AND expires_at > NOW()`, id,
	).Scan(&findingsJSON, &summaryJSON, &coverageJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ScanResponse{}, ErrNotFound
	}
	if err != nil {
		return model.ScanResponse{}, err
	}
	result := model.ScanResponse{ScanID: id, Findings: []model.Finding{}}
	if err := json.Unmarshal(findingsJSON, &result.Findings); err != nil {
		return model.ScanResponse{}, err
	}
	if err := json.Unmarshal(summaryJSON, &result.Summary); err != nil {
		return model.ScanResponse{}, err
	}
	if string(coverageJSON) != "null" {
		if err := json.Unmarshal(coverageJSON, &result.Coverage); err != nil {
			return model.ScanResponse{}, err
		}
	}
	return result, nil
}

func (s *Postgres) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scans WHERE expires_at <= NOW()`)
	return tag.RowsAffected(), err
}

func SanitizeResponse(response model.ScanResponse) model.ScanResponse {
	result := response
	result.Findings = append([]model.Finding{}, response.Findings...)
	for i := range result.Findings {
		finding := &result.Findings[i]
		finding.PageURL = RedactURL(finding.PageURL)
		finding.FormAction = RedactURL(finding.FormAction)
		finding.ResourceURL = RedactURL(finding.ResourceURL)
		finding.URL = RedactURL(finding.URL)
		finding.Location = RedactURL(finding.Location)
		finding.TestedURL = RedactURL(finding.TestedURL)
		for sampleIndex := range finding.SampleURLs {
			finding.SampleURLs[sampleIndex] = RedactURL(finding.SampleURLs[sampleIndex])
		}
		if finding.MarkerValue != "" {
			finding.MarkerValue = "[redacted]"
		}
		if finding.RequestOrigin != "" {
			finding.RequestOrigin = "https://[redacted].invalid"
		}
	}
	return result
}

func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return raw
	}
	query := parsed.Query()
	for key := range query {
		query.Set(key, "***")
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func newUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}
