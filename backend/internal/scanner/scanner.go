package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"trivy/backend/internal/model"
)

type Config struct {
	AllowPrivateTargets bool
	RequestTimeout      time.Duration
	MaxResponseBytes    int64
	UserAgent           string
	MaxPages            int
	MaxDepth            int
	MaxRequests         int
}

type Scanner struct {
	client           *http.Client
	maxResponseBytes int64
	userAgent        string
	maxPages         int
	maxDepth         int
	maxRequests      int
}

type probeResult struct {
	finding *model.Finding
	err     error
}

var databaseErrors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)warning.*mysql`),
	regexp.MustCompile(`(?i)unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)postgresql.*error|pg_query\(\)|pg::syntaxerror`),
	regexp.MustCompile(`(?i)sqlite[_ ]error|sqlite3?\.operationalerror`),
	regexp.MustCompile(`(?i)ora-[0-9]{5}`),
	regexp.MustCompile(`(?i)sqlstate\[[0-9a-z]+\]`),
}

func New(cfg Config) *Scanner {
	if cfg.MaxPages <= 0 {
		cfg.MaxPages = 25
	}
	if cfg.MaxDepth < 0 {
		cfg.MaxDepth = 0
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 100
	}
	dialer := &safeDialer{
		resolver:     net.DefaultResolver,
		dialer:       net.Dialer{Timeout: cfg.RequestTimeout, KeepAlive: 30 * time.Second},
		allowPrivate: cfg.AllowPrivateTargets,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   cfg.RequestTimeout,
		ResponseHeaderTimeout: cfg.RequestTimeout,
	}
	return &Scanner{
		client: &http.Client{
			Transport:     transport,
			Timeout:       cfg.RequestTimeout,
			CheckRedirect: redirectPolicy(cfg.AllowPrivateTargets),
		},
		maxResponseBytes: cfg.MaxResponseBytes,
		userAgent:        cfg.UserAgent,
		maxPages:         cfg.MaxPages,
		maxDepth:         cfg.MaxDepth,
		maxRequests:      cfg.MaxRequests,
	}
}

type Result struct {
	Findings []model.Finding
	Coverage model.Coverage
}

type crawlItem struct {
	url   *url.URL
	depth int
}

func (s *Scanner) Scan(ctx context.Context, target *url.URL, rate model.RateLimit, excluded []string) (Result, error) {
	if err := excludedPath(target, excluded); err != nil {
		return Result{}, err
	}
	limiter := &requestLimiter{
		interval: time.Second / time.Duration(rate.RequestsPerSecond),
		maximum:  s.maxRequests,
	}
	result := Result{Findings: []model.Finding{}, Coverage: model.Coverage{Warnings: []string{}}}
	queue := []crawlItem{{url: cloneURL(target), depth: 0}}
	seen := map[string]bool{normalizedURL(target): true}
	scriptsSeen := make(map[string]bool)

	for len(queue) > 0 && result.Coverage.PagesScanned < s.maxPages {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		item := queue[0]
		queue = queue[1:]
		if excludedPath(item.url, excluded) != nil {
			continue
		}
		baseline, err := s.fetch(ctx, item.url, "", limiter)
		if err != nil {
			if result.Coverage.PagesScanned == 0 {
				return Result{}, fmt.Errorf("baseline request failed: %w", err)
			}
			result.Coverage.Warnings = appendWarning(result.Coverage.Warnings, "a discovered page could not be fetched")
			if errors.Is(err, errRequestBudget) {
				result.Coverage.Truncated = true
				break
			}
			continue
		}
		result.Coverage.PagesScanned++
		analysis := analyzePage(item.url, baseline)
		result.Findings = append(result.Findings, analysis.findings...)
		result.Coverage.FormsDiscovered += analysis.forms

		beforeProbes := limiter.Count()
		probes := s.probePage(ctx, item.url, baseline, limiter, rate.MaxConcurrency)
		result.Coverage.ActiveProbes += limiter.Count() - beforeProbes
		result.Findings = append(result.Findings, probes.findings...)
		result.Coverage.ParametersTested += probes.parameters
		if probes.budgetExceeded {
			result.Coverage.Truncated = true
			break
		}
		for _, form := range analysis.postForms {
			if !sameOrigin(target, form.url) || excludedPath(form.url, excluded) != nil {
				continue
			}
			beforeProbes = limiter.Count()
			formProbes := s.probeTemplate(ctx, form, limiter, rate.MaxConcurrency)
			result.Coverage.ActiveProbes += limiter.Count() - beforeProbes
			result.Coverage.BodyParametersTested += formProbes.parameters
			result.Findings = append(result.Findings, formProbes.findings...)
			if formProbes.budgetExceeded {
				result.Coverage.Truncated = true
				break
			}
		}

		if item.depth < s.maxDepth {
			for _, candidate := range analysis.links {
				if !sameOrigin(target, candidate) || excludedPath(candidate, excluded) != nil {
					continue
				}
				key := normalizedURL(candidate)
				if !seen[key] {
					seen[key] = true
					queue = append(queue, crawlItem{url: candidate, depth: item.depth + 1})
				}
			}
			for _, scriptURL := range analysis.scripts {
				key := normalizedURL(scriptURL)
				if scriptsSeen[key] || !sameOrigin(target, scriptURL) {
					continue
				}
				scriptsSeen[key] = true
				script, fetchErr := s.fetch(ctx, scriptURL, "", limiter)
				if fetchErr != nil {
					if errors.Is(fetchErr, errRequestBudget) {
						result.Coverage.Truncated = true
						break
					}
					continue
				}
				for _, endpoint := range discoverScriptEndpoints(item.url, script.body) {
					if !sameOrigin(target, endpoint) || excludedPath(endpoint, excluded) != nil {
						continue
					}
					endpointKey := normalizedURL(endpoint)
					if !seen[endpointKey] {
						seen[endpointKey] = true
						queue = append(queue, crawlItem{url: endpoint, depth: item.depth + 1})
					}
					for _, template := range inferIntrusiveTemplates(endpoint) {
						beforeProbes := limiter.Count()
						templateProbes := s.probeTemplate(ctx, template, limiter, rate.MaxConcurrency)
						result.Coverage.ActiveProbes += limiter.Count() - beforeProbes
						result.Coverage.BodyParametersTested += templateProbes.parameters
						result.Findings = append(result.Findings, templateProbes.findings...)
						if templateProbes.budgetExceeded {
							result.Coverage.Truncated = true
							break
						}
					}
				}
			}
		}
	}
	result.Coverage.PagesDiscovered = len(seen)
	result.Coverage.RequestsMade = limiter.Count()
	if len(queue) > 0 || result.Coverage.PagesScanned >= s.maxPages && len(seen) > result.Coverage.PagesScanned {
		result.Coverage.Truncated = true
	}
	return result, nil
}

type pageProbeResult struct {
	findings       []model.Finding
	parameters     int
	budgetExceeded bool
}

func (s *Scanner) probePage(ctx context.Context, target *url.URL, baseline response, limiter *requestLimiter, concurrency int) pageProbeResult {
	type job func(context.Context) probeResult
	jobs := []job{func(ctx context.Context) probeResult { return s.corsProbe(ctx, target, limiter) }}
	for parameter := range target.Query() {
		name := parameter
		jobs = append(jobs,
			func(ctx context.Context) probeResult { return s.reflectionProbe(ctx, target, name, limiter) },
			func(ctx context.Context) probeResult {
				return s.sqlProbe(ctx, target, name, baseline, limiter)
			},
		)
	}
	semaphore := make(chan struct{}, concurrency)
	results := make(chan probeResult, len(jobs))
	var wg sync.WaitGroup
	for _, run := range jobs {
		semaphore <- struct{}{}
		wg.Add(1)
		go func(run job) {
			defer wg.Done()
			defer func() { <-semaphore }()
			results <- run(ctx)
		}(run)
	}
	wg.Wait()
	close(results)
	result := pageProbeResult{findings: []model.Finding{}, parameters: len(target.Query())}
	for probe := range results {
		if probe.finding != nil {
			result.findings = append(result.findings, *probe.finding)
		}
		if errors.Is(probe.err, errRequestBudget) {
			result.budgetExceeded = true
		}
	}
	return result
}

type response struct {
	body        string
	header      http.Header
	status      int
	contentType string
	finalURL    *url.URL
}

func (s *Scanner) fetch(ctx context.Context, target *url.URL, origin string, limiter *requestLimiter) (response, error) {
	return s.fetchRequest(ctx, http.MethodGet, target, "", "", origin, limiter)
}

func (s *Scanner) fetchRequest(ctx context.Context, method string, target *url.URL, contentType, body, origin string, limiter *requestLimiter) (response, error) {
	if err := limiter.Wait(ctx); err != nil {
		return response{}, err
	}
	var requestBody io.Reader
	if body != "" {
		requestBody = strings.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), requestBody)
	if err != nil {
		return response{}, err
	}
	request.Header.Set("User-Agent", s.userAgent)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	res, err := s.client.Do(request)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(res.Body, s.maxResponseBytes+1))
	if err != nil {
		return response{}, err
	}
	if int64(len(responseBody)) > s.maxResponseBytes {
		return response{}, fmt.Errorf("response exceeds size limit")
	}
	return response{
		body: string(responseBody), header: res.Header.Clone(), status: res.StatusCode,
		contentType: res.Header.Get("Content-Type"), finalURL: cloneURL(res.Request.URL),
	}, nil
}

func (s *Scanner) reflectionProbe(ctx context.Context, target *url.URL, parameter string, limiter *requestLimiter) probeResult {
	marker := "trivy_" + randomToken()
	payload := marker + `'"<>`
	probe := withParameter(target, parameter, payload)
	res, err := s.fetch(ctx, probe, "", limiter)
	if err != nil || !strings.Contains(res.body, marker) {
		return probeResult{err: err}
	}
	severity := model.SeverityMedium
	confidence := "heuristic"
	evidence := "unique marker was reflected; output context and encoding require review"
	if isHTMLResponse(res) && strings.Contains(res.body, payload) {
		severity = model.SeverityHigh
		confidence = "likely"
		evidence = "unique marker and HTML delimiter characters were reflected without encoding; possible reflected XSS surface"
	}
	return probeResult{finding: &model.Finding{
		Category: "reflected_input", PageURL: target.String(), Severity: severity,
		ParameterName: parameter, MarkerValue: marker, Confidence: confidence, Source: "http",
		Evidence: evidence, TestedURL: redactQueryValues(probe),
	}}
}

func isHTMLResponse(res response) bool {
	contentType := strings.ToLower(res.contentType)
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml") {
		return true
	}
	if contentType != "" {
		return false
	}
	prefix := strings.ToLower(res.body[:min(len(res.body), 256)])
	return strings.Contains(prefix, "<html") || strings.Contains(prefix, "<!doctype html")
}

func (s *Scanner) sqlProbe(ctx context.Context, target *url.URL, parameter string, baseline response, limiter *requestLimiter) probeResult {
	baselineErrors := errorMatches(baseline.body)
	for _, payload := range []string{"'", `"`} {
		probe := withParameter(target, parameter, payload)
		res, err := s.fetch(ctx, probe, "", limiter)
		if err != nil {
			if errors.Is(err, errRequestBudget) {
				return probeResult{err: err}
			}
			continue
		}
		for signature, snippet := range errorEvidence(res.body) {
			if !baselineErrors[signature] {
				return probeResult{finding: &model.Finding{
					Category: "sql_injection", PageURL: target.String(), Severity: model.SeverityHigh,
					ParameterName: parameter, EvidenceSnippet: snippet, Confidence: "heuristic", Source: "http",
					Evidence: "database error signature appeared only after a quote probe", TestedURL: redactQueryValues(probe),
				}}
			}
		}
	}
	original := target.Query().Get(parameter)
	trueValue, falseValue := booleanSQLValues(original)
	trueProbe := withParameter(target, parameter, trueValue)
	falseProbe := withParameter(target, parameter, falseValue)
	trueResponse, trueErr := s.fetch(ctx, trueProbe, "", limiter)
	if trueErr != nil {
		return probeResult{err: trueErr}
	}
	falseResponse, falseErr := s.fetch(ctx, falseProbe, "", limiter)
	if falseErr != nil {
		return probeResult{err: falseErr}
	}
	if likelyBooleanSQL(baseline, trueResponse, falseResponse) {
		return probeResult{finding: &model.Finding{
			Category: "sql_injection", PageURL: target.String(), Severity: model.SeverityHigh,
			ParameterName: parameter, Confidence: "heuristic", Source: "http",
			Evidence:  "true and false boolean conditions produced materially different responses while the true condition resembled the baseline",
			TestedURL: redactQueryValues(target),
		}}
	}
	return probeResult{}
}

// probeTemplate checks a form or discovered JSON endpoint with invalid canaries.
func (s *Scanner) probeTemplate(ctx context.Context, template requestTemplate, limiter *requestLimiter, concurrency int) pageProbeResult {
	if len(template.parameters) == 0 {
		return pageProbeResult{}
	}
	baselineBody, err := encodeTemplate(template, template.parameters)
	if err != nil {
		return pageProbeResult{}
	}
	baseline, err := s.fetchRequest(ctx, template.method, template.url, template.contentType, baselineBody, "", limiter)
	if err != nil {
		return pageProbeResult{budgetExceeded: errors.Is(err, errRequestBudget)}
	}
	result := pageProbeResult{findings: []model.Finding{}, parameters: len(template.parameters)}
	for parameter, original := range template.parameters {
		marker := "trivy_" + randomToken()
		values := cloneValues(template.parameters)
		values[parameter] = marker + `'"<>`
		body, encodeErr := encodeTemplate(template, values)
		if encodeErr != nil {
			continue
		}
		reflection, requestErr := s.fetchRequest(ctx, template.method, template.url, template.contentType, body, "", limiter)
		if requestErr != nil {
			result.budgetExceeded = result.budgetExceeded || errors.Is(requestErr, errRequestBudget)
			continue
		}
		if strings.Contains(reflection.body, marker) {
			severity, confidence, evidence := model.SeverityMedium, "heuristic", "unique body marker was reflected; output context requires review"
			if isHTMLResponse(reflection) && strings.Contains(reflection.body, marker+`'"<>`) {
				severity, confidence, evidence = model.SeverityHigh, "likely", "body marker and HTML delimiters were reflected without encoding; possible reflected XSS surface"
			}
			result.findings = append(result.findings, model.Finding{Category: "reflected_input", PageURL: template.url.String(), Severity: severity, ParameterName: parameter, MarkerValue: marker, Confidence: confidence, Source: "http", Evidence: evidence, TestedURL: template.url.String()})
		}

		quoteValues := cloneValues(template.parameters)
		quoteValues[parameter] = original + "'"
		quoteBody, encodeErr := encodeTemplate(template, quoteValues)
		if encodeErr != nil {
			continue
		}
		quoteResponse, requestErr := s.fetchRequest(ctx, template.method, template.url, template.contentType, quoteBody, "", limiter)
		if requestErr != nil {
			result.budgetExceeded = result.budgetExceeded || errors.Is(requestErr, errRequestBudget)
			continue
		}
		for signature, snippet := range errorEvidence(quoteResponse.body) {
			if !errorMatches(baseline.body)[signature] {
				result.findings = append(result.findings, model.Finding{Category: "sql_injection", PageURL: template.url.String(), Severity: model.SeverityHigh, ParameterName: parameter, EvidenceSnippet: snippet, Confidence: "heuristic", Source: "http", Evidence: "database error signature appeared only after an intrusive body quote probe", TestedURL: template.url.String()})
				break
			}
		}
	}
	return result
}

func encodeTemplate(template requestTemplate, values map[string]string) (string, error) {
	if template.contentType == "application/json" {
		encoded, err := json.Marshal(values)
		return string(encoded), err
	}
	form := url.Values{}
	for key, value := range values {
		form.Set(key, value)
	}
	return form.Encode(), nil
}

func cloneValues(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func inferIntrusiveTemplates(endpoint *url.URL) []requestTemplate {
	path := strings.ToLower(endpoint.Path)
	if strings.Contains(path, "login") || strings.Contains(path, "authenticate") {
		return []requestTemplate{{url: cloneURL(endpoint), method: http.MethodPost, contentType: "application/json", parameters: map[string]string{"email": "scanner@example.invalid", "password": "invalid-password"}}}
	}
	if strings.Contains(path, "search") {
		return []requestTemplate{{url: cloneURL(endpoint), method: http.MethodPost, contentType: "application/json", parameters: map[string]string{"q": "trivy"}}}
	}
	return nil
}

var numericInput = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]+)?$`)

func booleanSQLValues(original string) (string, string) {
	if numericInput.MatchString(strings.TrimSpace(original)) {
		return original + " AND 1=1", original + " AND 1=2"
	}
	return original + "' AND '1'='1", original + "' AND '1'='2"
}

func likelyBooleanSQL(baseline, trueResponse, falseResponse response) bool {
	if trueResponse.status == baseline.status && falseResponse.status != baseline.status {
		return true
	}
	baselineLength := len(baseline.body)
	trueDelta := absoluteDifference(len(trueResponse.body), baselineLength)
	falseDelta := absoluteDifference(len(falseResponse.body), baselineLength)
	minimumDifference := max(64, baselineLength/10)
	trueTolerance := max(32, baselineLength/20)
	return trueResponse.status == baseline.status && trueDelta <= trueTolerance && falseDelta >= minimumDifference &&
		absoluteDifference(len(trueResponse.body), len(falseResponse.body)) >= minimumDifference
}

func absoluteDifference(left, right int) int {
	if left > right {
		return left - right
	}
	return right - left
}

func (s *Scanner) corsProbe(ctx context.Context, target *url.URL, limiter *requestLimiter) probeResult {
	origin := "https://" + randomToken() + ".invalid"
	res, err := s.fetch(ctx, target, origin, limiter)
	if err != nil {
		return probeResult{err: err}
	}
	acao := strings.TrimSpace(res.header.Get("Access-Control-Allow-Origin"))
	credentials := strings.EqualFold(strings.TrimSpace(res.header.Get("Access-Control-Allow-Credentials")), "true")
	if acao != origin && !(acao == "*" && credentials) {
		return probeResult{}
	}
	severity := model.SeverityMedium
	if credentials {
		severity = model.SeverityHigh
	}
	return probeResult{finding: &model.Finding{
		Category: "cors_misconfig", PageURL: target.String(), Severity: severity,
		RequestOrigin: origin, ReflectedACAOValue: acao, AllowsCredentials: boolPtr(credentials),
		Confidence: "likely", Source: "http", Evidence: "server accepted an untrusted Origin value",
		TestedURL: redactQueryValues(target),
	}}
}

func withParameter(target *url.URL, name, value string) *url.URL {
	clone := *target
	query := clone.Query()
	query.Set(name, value)
	clone.RawQuery = query.Encode()
	return &clone
}

func excludedPath(target *url.URL, excluded []string) error {
	path, err := url.PathUnescape(target.EscapedPath())
	if err != nil {
		return fmt.Errorf("invalid target path")
	}
	for _, prefix := range excluded {
		if strings.HasPrefix(path, prefix) {
			return fmt.Errorf("target path is excluded from active scanning")
		}
	}
	return nil
}

func errorMatches(body string) map[string]bool {
	result := make(map[string]bool)
	for _, pattern := range databaseErrors {
		if pattern.MatchString(body) {
			result[pattern.String()] = true
		}
	}
	return result
}

func errorEvidence(body string) map[string]string {
	result := make(map[string]string)
	for _, pattern := range databaseErrors {
		location := pattern.FindStringIndex(body)
		if location == nil {
			continue
		}
		snippet := strings.Join(strings.Fields(body[location[0]:location[1]]), " ")
		if len(snippet) > 160 {
			snippet = snippet[:160]
		}
		result[pattern.String()] = snippet
	}
	return result
}

func randomToken() string {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value)
}

func boolPtr(value bool) *bool       { return &value }
func stringPtr(value string) *string { return &value }

type requestLimiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
	maximum  int
	count    int
}

var errRequestBudget = errors.New("scan request budget exhausted")

func (l *requestLimiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	if l.count >= l.maximum {
		l.mu.Unlock()
		return errRequestBudget
	}
	l.count++
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := time.Until(l.next)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (l *requestLimiter) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}
