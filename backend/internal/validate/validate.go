package validate

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"trivy/backend/internal/model"
)

var severities = []model.Severity{
	model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo,
}

var clientCategories = map[string]bool{
	"header": true, "insecure_form": true, "unencrypted_credentials": true,
	"mixed_content": true, "sensitive_url": true, "insecure_cookie": true,
	"exposed_secret": true, "vulnerable_library": true, "sensitive_storage": true,
}

var knownHeaders = map[string]bool{
	"content-security-policy": true, "strict-transport-security": true,
	"x-content-type-options": true, "x-frame-options": true,
	"referrer-policy": true, "permissions-policy": true,
	"cross-origin-opener-policy": true, "cross-origin-resource-policy": true,
	"access-control-allow-origin": true,
}

var sensitiveCookieName = regexp.MustCompile(`(?i)(session|auth|token|jwt|sid|identity|account)`)

func Request(req *model.ScanRequest, maxRPS, maxConcurrency int) (*url.URL, error) {
	if req.ScanMode != "passive" && req.ScanMode != "active" && req.ScanMode != "combined" {
		return nil, fmt.Errorf("scanMode must be passive, active, or combined")
	}
	if req.Findings == nil {
		return nil, fmt.Errorf("findings must be an array")
	}
	if req.ScanMode != "passive" && !req.Consent {
		return nil, fmt.Errorf("consent is required for active or combined scans")
	}
	target, err := HTTPURL(req.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	for i := range req.Findings {
		if err := Finding(&req.Findings[i]); err != nil {
			return nil, fmt.Errorf("finding %d: %w", i, err)
		}
	}
	req.Findings = Deduplicate(req.Findings)

	if req.ScanMode != "passive" {
		if req.RateLimit == nil {
			req.RateLimit = &model.RateLimit{RequestsPerSecond: 3, MaxConcurrency: 2}
		}
		req.RateLimit.RequestsPerSecond = clamp(req.RateLimit.RequestsPerSecond, 1, maxRPS)
		req.RateLimit.MaxConcurrency = clamp(req.RateLimit.MaxConcurrency, 1, maxConcurrency)
	}
	for i, path := range req.ExcludedPaths {
		if path == "" || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("excludedPaths[%d] must begin with /", i)
		}
		cleaned, err := url.PathUnescape(path)
		if err != nil || strings.Contains(cleaned, "\x00") {
			return nil, fmt.Errorf("excludedPaths[%d] is invalid", i)
		}
		req.ExcludedPaths[i] = cleaned
	}
	return target, nil
}

func HTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("must be an absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	if u.User != nil {
		return nil, fmt.Errorf("embedded credentials are not allowed")
	}
	if u.Fragment != "" {
		u.Fragment = ""
	}
	return u, nil
}

func Finding(f *model.Finding) error {
	if !clientCategories[f.Category] {
		return fmt.Errorf("unknown or backend-owned category %q", f.Category)
	}
	if _, err := HTTPURL(f.PageURL); err != nil {
		return fmt.Errorf("invalid pageUrl: %w", err)
	}
	if !slices.Contains(severities, f.Severity) {
		return fmt.Errorf("invalid severity %q", f.Severity)
	}
	if f.Confidence != "" && !oneOf(f.Confidence, "confirmed", "likely", "heuristic", "informational") {
		return fmt.Errorf("invalid confidence %q", f.Confidence)
	}
	if f.Source != "" && !oneOf(f.Source, "http", "browser", "extension") {
		return fmt.Errorf("invalid source %q", f.Source)
	}

	switch f.Category {
	case "header":
		f.Header = strings.ToLower(f.Header)
		if !knownHeaders[f.Header] || !oneOf(f.Status, "missing", "weak", "ok") {
			return fmt.Errorf("invalid header finding")
		}
		f.Severity = headerSeverity(f.Header, f.Status)
	case "insecure_form":
		if _, err := HTTPURL(f.FormAction); err != nil || !oneOf(f.Method, "GET", "POST") ||
			f.HasPasswordField == nil || f.IsActionInsecure == nil || f.AutocompleteOnSensitive == nil || f.HasCSRFToken == nil {
			return fmt.Errorf("invalid insecure form finding")
		}
		if *f.HasPasswordField && *f.IsActionInsecure {
			f.Severity = model.SeverityHigh
		} else {
			f.Severity = model.SeverityMedium
		}
	case "unencrypted_credentials":
		action, actionErr := HTTPURL(f.FormAction)
		if actionErr != nil || action.Scheme != "http" || !isTrue(f.HasPasswordField) || !isTrue(f.IsHTTP) {
			return fmt.Errorf("invalid unencrypted credentials finding")
		}
		f.Severity = model.SeverityHigh
	case "mixed_content":
		page, pageErr := HTTPURL(f.PageURL)
		resource, resourceErr := HTTPURL(f.ResourceURL)
		if pageErr != nil || resourceErr != nil || page.Scheme != "https" || resource.Scheme != "http" ||
			!oneOf(f.ResourceType, "script", "image", "stylesheet", "iframe", "font") {
			return fmt.Errorf("invalid mixed content finding")
		}
		if f.ResourceType == "script" || f.ResourceType == "iframe" {
			f.Severity = model.SeverityHigh
		} else {
			f.Severity = model.SeverityLow
		}
	case "sensitive_url":
		if _, err := HTTPURL(f.URL); err != nil || !strings.Contains(f.URL, "***") || f.ParameterName == "" || f.MatchReason == "" {
			return fmt.Errorf("sensitive URL must be valid, redacted, and described")
		}
	case "insecure_cookie":
		if f.CookieName == "" || f.MissingSecure == nil || f.MissingHTTPOnly == nil || f.MissingSameSite == nil {
			return fmt.Errorf("invalid insecure cookie finding")
		}
		f.Severity = cookieSeverity(f.CookieName, *f.MissingSecure, *f.MissingHTTPOnly, *f.MissingSameSite)
	case "exposed_secret":
		if f.SecretType == "" || f.Location == "" {
			return fmt.Errorf("invalid exposed secret finding")
		}
	case "vulnerable_library":
		if f.LibraryName == "" || f.DetectedVersion == "" {
			return fmt.Errorf("invalid vulnerable library finding")
		}
	case "sensitive_storage":
		if !oneOf(f.StorageType, "localStorage", "sessionStorage") || f.KeyName == "" || f.Reason == "" {
			return fmt.Errorf("invalid sensitive storage finding")
		}
	}
	return nil
}

func Deduplicate(findings []model.Finding) []model.Finding {
	seen := make(map[string]int, len(findings))
	affected := make(map[string]map[string]struct{}, len(findings))
	result := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		key := findingKey(finding)
		if index, ok := seen[key]; ok {
			if mergeableFinding(finding.Category) {
				mergeFindingMetadata(&result[index], finding)
				mergeAffectedPage(&result[index], finding.PageURL, affected[key])
			}
			continue
		}
		seen[key] = len(result)
		if mergeableFinding(finding.Category) {
			finding.AffectedPages = 0
			affected[key] = make(map[string]struct{})
			if finding.PageURL != "" {
				finding.AffectedPages = 1
				finding.SampleURLs = []string{finding.PageURL}
				affected[key][canonicalPageURL(finding.PageURL)] = struct{}{}
			}
		}
		result = append(result, finding)
	}
	return result
}

func mergeableFinding(category string) bool {
	return oneOf(category, "header", "insecure_cookie", "vulnerable_library", "mixed_content")
}

func mergeAffectedPage(existing *model.Finding, pageURL string, pages map[string]struct{}) {
	if pageURL == "" {
		return
	}
	canonical := canonicalPageURL(pageURL)
	if _, exists := pages[canonical]; exists {
		return
	}
	pages[canonical] = struct{}{}
	existing.AffectedPages++
	if len(existing.SampleURLs) < 5 {
		existing.SampleURLs = append(existing.SampleURLs, pageURL)
	}
}

func mergeFindingMetadata(existing *model.Finding, incoming model.Finding) {
	if severityRank(incoming.Severity) > severityRank(existing.Severity) {
		existing.Severity = incoming.Severity
	}
	if existing.Confidence == "" {
		existing.Confidence = incoming.Confidence
	}
	if existing.Source == "" {
		existing.Source = incoming.Source
	}
	if existing.Evidence == "" {
		existing.Evidence = incoming.Evidence
	}
}

func canonicalPageURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.Fragment = ""
	return parsed.String()
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func headerSeverity(header, status string) model.Severity {
	if status == "ok" {
		return model.SeverityInfo
	}
	switch header {
	case "content-security-policy", "strict-transport-security", "x-frame-options":
		if status == "weak" && header == "strict-transport-security" {
			return model.SeverityLow
		}
		return model.SeverityMedium
	case "referrer-policy", "permissions-policy":
		return model.SeverityInfo
	default:
		return model.SeverityLow
	}
}

func cookieSeverity(name string, missingSecure, missingHTTPOnly, missingSameSite bool) model.Severity {
	if !sensitiveCookieName.MatchString(name) {
		return model.SeverityLow
	}
	if missingSecure && missingHTTPOnly {
		return model.SeverityHigh
	}
	if missingSecure || missingHTTPOnly || missingSameSite {
		return model.SeverityMedium
	}
	return model.SeverityInfo
}

func findingKey(finding model.Finding) string {
	switch finding.Category {
	case "header":
		return fmt.Sprintf("header|%s|%s", finding.Header, finding.Status)
	case "insecure_cookie":
		return fmt.Sprintf("cookie|%s|%v|%v|%v", finding.CookieName, pointerValue(finding.MissingSecure), pointerValue(finding.MissingHTTPOnly), pointerValue(finding.MissingSameSite))
	case "vulnerable_library":
		return fmt.Sprintf("library|%s|%s|%s", finding.LibraryName, finding.DetectedVersion, finding.KnownCVE)
	case "mixed_content":
		return fmt.Sprintf("mixed|%s|%s", finding.ResourceURL, finding.ResourceType)
	default:
		encoded, _ := json.Marshal(finding)
		return string(encoded)
	}
}

func pointerValue(value *bool) string {
	if value == nil {
		return "unset"
	}
	if *value {
		return "true"
	}
	return "false"
}

func Summary(findings []model.Finding) model.Summary {
	var result model.Summary
	for _, finding := range findings {
		switch finding.Severity {
		case model.SeverityCritical:
			result.Critical++
		case model.SeverityHigh:
			result.High++
		case model.SeverityMedium:
			result.Medium++
		case model.SeverityLow:
			result.Low++
		case model.SeverityInfo:
			result.Info++
		}
	}
	return result
}

func clamp(value, minimum, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }
func isTrue(value *bool) bool                    { return value != nil && *value }
