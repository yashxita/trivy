package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"trivy/backend/internal/model"
)

func TestScanFindsReflectionAndCORS(t *testing.T) {
	target, _ := url.Parse("https://example.com/?q=hello")
	scanner := New(Config{AllowPrivateTargets: true, RequestTimeout: time.Second, MaxResponseBytes: 1 << 20, UserAgent: "test"})
	scanner.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		origin := r.Header.Get("Origin")
		headers := make(http.Header)
		if origin != "" {
			headers.Set("Access-Control-Allow-Origin", origin)
			headers.Set("Access-Control-Allow-Credentials", "true")
		}
		headers.Set("Content-Type", "text/html")
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: ioNopCloser{Reader: strings.NewReader(fmt.Sprintf("value=%s", r.URL.Query().Get("q")))}, Request: r}, nil
	})
	result, err := scanner.Scan(context.Background(), target, model.RateLimit{RequestsPerSecond: 100, MaxConcurrency: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var reflected, cors bool
	for _, finding := range result.Findings {
		if finding.Category == "reflected_input" {
			reflected = true
			if finding.Severity != model.SeverityHigh || finding.Confidence != "likely" {
				t.Fatalf("reflection finding = %#v, want likely High contextual reflection", finding)
			}
		}
		cors = cors || finding.Category == "cors_misconfig"
	}
	if !reflected || !cors {
		t.Fatalf("findings = %#v, expected reflection and CORS findings", result.Findings)
	}
}

func TestReflectionInJSONIsNotClassifiedAsLikelyXSS(t *testing.T) {
	target, _ := url.Parse("https://example.com/api?q=hello")
	scanner := New(Config{AllowPrivateTargets: true, RequestTimeout: time.Second, MaxResponseBytes: 1 << 20, UserAgent: "test"})
	scanner.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		headers := make(http.Header)
		headers.Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"value":%q}`, r.URL.Query().Get("q"))
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: ioNopCloser{Reader: strings.NewReader(body)}, Request: r}, nil
	})
	result, err := scanner.Scan(context.Background(), target, model.RateLimit{RequestsPerSecond: 100, MaxConcurrency: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if finding.Category == "reflected_input" && (finding.Severity != model.SeverityMedium || finding.Confidence != "heuristic") {
			t.Fatalf("JSON reflection finding = %#v, want heuristic Medium", finding)
		}
	}
}

func TestLikelyBooleanSQL(t *testing.T) {
	baseline := response{status: 200, body: strings.Repeat("a", 1000)}
	trueResponse := response{status: 200, body: strings.Repeat("a", 990)}
	falseResponse := response{status: 200, body: strings.Repeat("b", 600)}
	if !likelyBooleanSQL(baseline, trueResponse, falseResponse) {
		t.Fatal("expected differential boolean SQL signal")
	}
	if likelyBooleanSQL(baseline, trueResponse, response{status: 200, body: strings.Repeat("b", 980)}) {
		t.Fatal("similar response sizes should not produce a SQL signal")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type ioNopCloser struct{ *strings.Reader }

func (ioNopCloser) Close() error { return nil }

func TestScanHonorsExcludedPath(t *testing.T) {
	target, _ := url.Parse("https://example.com/logout")
	scanner := New(Config{AllowPrivateTargets: true, RequestTimeout: time.Second, MaxResponseBytes: 1 << 20})
	_, err := scanner.Scan(context.Background(), target, model.RateLimit{RequestsPerSecond: 100, MaxConcurrency: 1}, []string{"/logout"})
	if err == nil || !strings.Contains(err.Error(), "excluded") {
		t.Fatalf("error = %v, expected excluded-path error", err)
	}
}

func TestScanCrawlsSameOriginAndReportsCoverage(t *testing.T) {
	target, _ := url.Parse("https://example.com/")
	scanner := New(Config{
		AllowPrivateTargets: true, RequestTimeout: time.Second, MaxResponseBytes: 1 << 20,
		MaxPages: 5, MaxDepth: 1, MaxRequests: 20,
	})
	scanner.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `<html><a href="/next?q=hello">next</a></html>`
		if r.URL.Path == "/next" {
			body = `<html>value=` + r.URL.Query().Get("q") + `</html>`
		}
		headers := make(http.Header)
		headers.Set("Content-Type", "text/html")
		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: ioNopCloser{Reader: strings.NewReader(body)}, Request: r}, nil
	})
	result, err := scanner.Scan(context.Background(), target, model.RateLimit{RequestsPerSecond: 1000, MaxConcurrency: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Coverage.PagesScanned != 2 || result.Coverage.PagesDiscovered != 2 {
		t.Fatalf("coverage = %#v, want two discovered and scanned pages", result.Coverage)
	}
	if result.Coverage.ParametersTested != 1 {
		t.Fatalf("parameters tested = %d, want 1", result.Coverage.ParametersTested)
	}
	var reflected bool
	for _, finding := range result.Findings {
		reflected = reflected || finding.Category == "reflected_input" && finding.ParameterName == "q"
	}
	if !reflected {
		t.Fatalf("findings = %#v, expected reflection on discovered URL", result.Findings)
	}
}

func TestCookieSeverityUsesSensitivity(t *testing.T) {
	headers := make(http.Header)
	headers.Add("Set-Cookie", "language=en; Path=/; SameSite=Lax")
	headers.Add("Set-Cookie", "session=abc; Path=/; SameSite=Lax")
	page, _ := url.Parse("https://example.com/")
	findings := cookieFindings(page, headers)
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want two cookie findings", findings)
	}
	severities := map[string]model.Severity{}
	for _, finding := range findings {
		severities[finding.CookieName] = finding.Severity
	}
	if severities["language"] != model.SeverityLow || severities["session"] != model.SeverityHigh {
		t.Fatalf("cookie severities = %#v", severities)
	}
}

func TestHeaderPolicyIsContentAware(t *testing.T) {
	page, _ := url.Parse("https://example.com/api")
	headers := make(http.Header)
	findings := headerFindings(page, headers, false, http.StatusOK)
	for _, finding := range findings {
		if finding.Header == "content-security-policy" || finding.Header == "referrer-policy" || finding.Header == "permissions-policy" || finding.Header == "x-frame-options" {
			t.Fatalf("document-only header %q reported for JSON/API response", finding.Header)
		}
	}
	if got := headerFindings(page, headers, true, http.StatusNotFound); len(got) != 0 {
		t.Fatalf("error response findings = %#v, want none", got)
	}
}

func TestFrameAncestorsReplacesXFrameOptions(t *testing.T) {
	page, _ := url.Parse("https://example.com/")
	headers := make(http.Header)
	headers.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("Strict-Transport-Security", "max-age=31536000")
	findings := headerFindings(page, headers, true, http.StatusOK)
	for _, finding := range findings {
		if finding.Header == "x-frame-options" {
			t.Fatalf("X-Frame-Options reported despite CSP frame-ancestors: %#v", findings)
		}
	}
}
