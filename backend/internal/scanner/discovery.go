package scanner

import (
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"trivy/backend/internal/model"
)

type pageAnalysis struct {
	links    []*url.URL
	scripts  []*url.URL
	findings []model.Finding
	forms    int
	postForms []requestTemplate
}

type requestTemplate struct {
	url         *url.URL
	method      string
	contentType string
	parameters  map[string]string
}

type headerRule struct {
	name         string
	severity     model.Severity
	documentOnly bool
}

var securityHeaders = []headerRule{
	{name: "Content-Security-Policy", severity: model.SeverityMedium, documentOnly: true},
	{name: "X-Content-Type-Options", severity: model.SeverityLow},
	{name: "Referrer-Policy", severity: model.SeverityInfo, documentOnly: true},
	{name: "Permissions-Policy", severity: model.SeverityInfo, documentOnly: true},
}

var sensitiveCookieName = regexp.MustCompile(`(?i)(session|auth|token|jwt|sid|identity|account)`)
var scriptEndpoint = regexp.MustCompile("[\"'`]((?:https?://[^\"'`\\s]+)|(?:/(?:api|rest|graphql)/[^\"'`\\s?#]*)(?:\\?[^\"'`\\s#]*)?)[\"'`]")

var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{name: "jwt", pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{name: "private_key", pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{name: "api_key", pattern: regexp.MustCompile(`(?i)(?:api[_-]?key|secret[_-]?key)["'\s:=]{1,8}[A-Za-z0-9_-]{16,}`)},
}

var libraryPatterns = []struct {
	name       string
	pattern    *regexp.Regexp
	knownCVE   string
	vulnerable func(string) bool
}{
	{name: "jQuery", pattern: regexp.MustCompile(`(?i)jquery[.-]([0-9.]+)(?:\.min)?\.js`), knownCVE: "CVE-2020-11022", vulnerable: func(v string) bool { return versionLessThan(v, "3.5.0") }},
	{name: "Lodash", pattern: regexp.MustCompile(`(?i)lodash[.-]([0-9.]+)(?:\.min)?\.js`), knownCVE: "CVE-2021-23337", vulnerable: func(v string) bool { return versionLessThan(v, "4.17.21") }},
}

func analyzePage(pageURL *url.URL, res response) pageAnalysis {
	result := pageAnalysis{links: []*url.URL{}, scripts: []*url.URL{}, findings: []model.Finding{}, postForms: []requestTemplate{}}
	isHTML := strings.Contains(strings.ToLower(res.contentType), "html") || strings.Contains(strings.ToLower(res.body[:min(len(res.body), 256)]), "<html")
	result.findings = append(result.findings, headerFindings(pageURL, res.header, isHTML, res.status)...)
	result.findings = append(result.findings, cookieFindings(pageURL, res.header)...)
	result.findings = append(result.findings, exposedSecretFindings(pageURL, res.body)...)
	if !isHTML {
		return result
	}
	document, err := html.Parse(strings.NewReader(res.body))
	if err != nil {
		return result
	}
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "a":
				if candidate := resolveURL(pageURL, attribute(node, "href")); candidate != nil {
					result.links = append(result.links, candidate)
				}
			case "form":
				result.forms++
				analyzeForm(pageURL, node, &result)
			case "script":
				analyzeResource(pageURL, node, "src", "script", &result)
			case "iframe":
				analyzeResource(pageURL, node, "src", "iframe", &result)
			case "img":
				analyzeResource(pageURL, node, "src", "image", &result)
			case "link":
				analyzeResource(pageURL, node, "href", "stylesheet", &result)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	return result
}

func headerFindings(pageURL *url.URL, headers http.Header, isHTML bool, status int) []model.Finding {
	findings := []model.Finding{}
	if status >= 400 {
		return findings
	}
	for _, rule := range securityHeaders {
		if rule.documentOnly && !isHTML {
			continue
		}
		if headers.Get(rule.name) == "" {
			findings = append(findings, model.Finding{
				Category: "header", PageURL: pageURL.String(), Severity: rule.severity,
				Header: strings.ToLower(rule.name), Status: "missing", Confidence: "confirmed",
				Source: "http", Evidence: rule.name + " response header is absent",
			})
		}
	}
	csp := headers.Get("Content-Security-Policy")
	if isHTML && csp != "" && (strings.Contains(strings.ToLower(csp), "'unsafe-inline'") || strings.Contains(strings.ToLower(csp), "'unsafe-eval'")) {
		findings = append(findings, model.Finding{
			Category: "header", PageURL: pageURL.String(), Severity: model.SeverityMedium,
			Header: "content-security-policy", Value: stringPtr(csp), Status: "weak", Confidence: "heuristic",
			Source: "http", Evidence: "Content-Security-Policy permits unsafe-inline or unsafe-eval",
		})
	}
	if isHTML && headers.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		findings = append(findings, model.Finding{
			Category: "header", PageURL: pageURL.String(), Severity: model.SeverityMedium,
			Header: "x-frame-options", Status: "missing", Confidence: "confirmed",
			Source: "http", Evidence: "neither X-Frame-Options nor CSP frame-ancestors is present",
		})
	}
	contentTypeOptions := headers.Get("X-Content-Type-Options")
	if contentTypeOptions != "" && !strings.EqualFold(strings.TrimSpace(contentTypeOptions), "nosniff") {
		findings = append(findings, model.Finding{
			Category: "header", PageURL: pageURL.String(), Severity: model.SeverityLow,
			Header: "x-content-type-options", Value: stringPtr(contentTypeOptions), Status: "weak", Confidence: "confirmed",
			Source: "http", Evidence: "X-Content-Type-Options is present but is not nosniff",
		})
	}
	hsts := headers.Get("Strict-Transport-Security")
	if pageURL.Scheme == "https" && hsts == "" {
		findings = append(findings, model.Finding{
			Category: "header", PageURL: pageURL.String(), Severity: model.SeverityMedium,
			Header: "strict-transport-security", Status: "missing", Confidence: "confirmed",
			Source: "http", Evidence: "Strict-Transport-Security response header is absent",
		})
	} else if pageURL.Scheme == "https" && !strongHSTS(hsts) {
		findings = append(findings, model.Finding{
			Category: "header", PageURL: pageURL.String(), Severity: model.SeverityLow,
			Header: "strict-transport-security", Value: stringPtr(hsts), Status: "weak", Confidence: "heuristic",
			Source: "http", Evidence: "HSTS max-age is shorter than 180 days",
		})
	}
	return findings
}

var hstsMaxAge = regexp.MustCompile(`(?i)(?:^|;)\s*max-age\s*=\s*([0-9]+)`)

func strongHSTS(value string) bool {
	match := hstsMaxAge.FindStringSubmatch(value)
	if len(match) != 2 {
		return false
	}
	seconds := 0
	for _, character := range match[1] {
		seconds = seconds*10 + int(character-'0')
	}
	return seconds >= 15552000
}

func cookieFindings(pageURL *url.URL, headers http.Header) []model.Finding {
	response := &http.Response{Header: headers}
	findings := []model.Finding{}
	for _, cookie := range response.Cookies() {
		missingSecure := !cookie.Secure
		missingHTTPOnly := !cookie.HttpOnly
		missingSameSite := cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == http.SameSiteNoneMode
		sensitive := sensitiveCookieName.MatchString(cookie.Name)
		if !missingSecure && (!sensitive || !missingHTTPOnly) && !missingSameSite {
			continue
		}
		severity := model.SeverityLow
		if sensitive && missingSecure && missingHTTPOnly {
			severity = model.SeverityHigh
		} else if sensitive && (missingSecure || missingHTTPOnly || missingSameSite) {
			severity = model.SeverityMedium
		}
		findings = append(findings, model.Finding{
			Category: "insecure_cookie", PageURL: pageURL.String(), Severity: severity,
			CookieName: cookie.Name, MissingSecure: boolPtr(missingSecure), MissingHTTPOnly: boolPtr(missingHTTPOnly),
			MissingSameSite: boolPtr(missingSameSite), Confidence: "heuristic", Source: "http",
			Evidence: "cookie attributes may permit transport, script, or cross-site exposure",
		})
	}
	return findings
}

func analyzeForm(pageURL *url.URL, form *html.Node, result *pageAnalysis) {
	action := resolveURL(pageURL, attribute(form, "action"))
	if action == nil {
		action = cloneURL(pageURL)
	}
	method := strings.ToUpper(attribute(form, "method"))
	if method != "POST" {
		method = "GET"
	}
	hasPassword, hasCSRF := false, false
	parameters := make(map[string]string)
	var inspect func(*html.Node)
	inspect = func(node *html.Node) {
		if node.Type == html.ElementNode && (node.Data == "input" || node.Data == "textarea" || node.Data == "select") {
			name := attribute(node, "name")
			typeName := strings.ToLower(attribute(node, "type"))
			hasPassword = hasPassword || typeName == "password"
			hasCSRF = hasCSRF || strings.Contains(strings.ToLower(name), "csrf") || strings.Contains(strings.ToLower(name), "token")
			if name != "" && typeName != "submit" && typeName != "button" {
				value := attribute(node, "value")
				if value == "" && typeName == "email" {
					value = "scanner@example.invalid"
				} else if value == "" && typeName == "password" {
					value = "TrivyInvalidPassword1!"
				} else if value == "" {
					value = "trivy"
				}
				parameters[name] = value
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			inspect(child)
		}
	}
	inspect(form)
	insecureAction := pageURL.Scheme == "https" && action.Scheme == "http"
	if insecureAction || method == "POST" && !hasCSRF {
		severity := model.SeverityMedium
		if insecureAction && hasPassword {
			severity = model.SeverityHigh
		}
		result.findings = append(result.findings, model.Finding{
			Category: "insecure_form", PageURL: pageURL.String(), Severity: severity,
			FormAction: action.String(), Method: method, HasPasswordField: boolPtr(hasPassword),
			IsActionInsecure: boolPtr(insecureAction), AutocompleteOnSensitive: boolPtr(false), HasCSRFToken: boolPtr(hasCSRF),
			Confidence: "heuristic", Source: "http", Evidence: "form action or anti-CSRF field requires review",
		})
	}
	if method == "GET" && len(parameters) > 0 {
		query := action.Query()
		for name, value := range parameters {
			if !query.Has(name) {
				query.Set(name, value)
			}
		}
		action.RawQuery = query.Encode()
		result.links = append(result.links, action)
	} else if method == "POST" && len(parameters) > 0 && !hasCSRF {
		result.postForms = append(result.postForms, requestTemplate{
			url: action, method: http.MethodPost, contentType: "application/x-www-form-urlencoded", parameters: parameters,
		})
	}
}

func analyzeResource(pageURL *url.URL, node *html.Node, attributeName, resourceType string, result *pageAnalysis) {
	resource := resolveURL(pageURL, attribute(node, attributeName))
	if resource == nil {
		return
	}
	if resourceType == "script" {
		result.scripts = append(result.scripts, resource)
		for _, library := range libraryPatterns {
			match := library.pattern.FindStringSubmatch(resource.String())
			if len(match) > 1 && library.vulnerable(match[1]) {
				result.findings = append(result.findings, model.Finding{
					Category: "vulnerable_library", PageURL: pageURL.String(), Severity: model.SeverityHigh,
					LibraryName: library.name, DetectedVersion: match[1], KnownCVE: library.knownCVE,
					Confidence: "likely", Source: "http", Evidence: "script URL contains a known vulnerable version",
				})
			}
		}
	}
	if pageURL.Scheme == "https" && resource.Scheme == "http" {
		severity := model.SeverityLow
		if resourceType == "script" || resourceType == "iframe" {
			severity = model.SeverityHigh
		}
		result.findings = append(result.findings, model.Finding{
			Category: "mixed_content", PageURL: pageURL.String(), Severity: severity,
			ResourceURL: resource.String(), ResourceType: resourceType, Confidence: "confirmed",
			Source: "http", Evidence: "HTTPS page references an HTTP resource",
		})
	}
}

func exposedSecretFindings(pageURL *url.URL, body string) []model.Finding {
	findings := []model.Finding{}
	for _, secret := range secretPatterns {
		if secret.pattern.MatchString(body) {
			findings = append(findings, model.Finding{
				Category: "exposed_secret", PageURL: pageURL.String(), Severity: model.SeverityHigh,
				SecretType: secret.name, Location: redactQueryValues(pageURL), Confidence: "heuristic",
				Source: "http", Evidence: "response body matches a secret-shaped pattern; value omitted",
			})
		}
	}
	return findings
}

func discoverScriptEndpoints(base *url.URL, source string) []*url.URL {
	result := []*url.URL{}
	for _, match := range scriptEndpoint.FindAllStringSubmatch(source, 100) {
		if len(match) < 2 || strings.ContainsAny(match[1], "{}<>") {
			continue
		}
		candidate := resolveURL(base, strings.ReplaceAll(match[1], `\/`, `/`))
		if candidate == nil {
			continue
		}
		if len(candidate.Query()) == 0 && strings.Contains(strings.ToLower(candidate.Path), "search") {
			query := candidate.Query()
			query.Set("q", "trivy")
			candidate.RawQuery = query.Encode()
		}
		result = append(result, candidate)
	}
	return result
}

func resolveURL(base *url.URL, raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "data:") {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil
	}
	resolved.Fragment = ""
	return resolved
}

func attribute(node *html.Node, name string) string {
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, name) {
			return attribute.Val
		}
	}
	return ""
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func normalizedURL(value *url.URL) string {
	clone := cloneURL(value)
	clone.Fragment = ""
	clone.Path = path.Clean("/" + strings.TrimPrefix(clone.Path, "/"))
	clone.RawQuery = clone.Query().Encode()
	return clone.String()
}

func cloneURL(value *url.URL) *url.URL {
	clone := *value
	return &clone
}

func redactQueryValues(value *url.URL) string {
	clone := cloneURL(value)
	query := clone.Query()
	for key := range query {
		query.Set(key, "***")
	}
	clone.RawQuery = query.Encode()
	clone.Fragment = ""
	return clone.String()
}

func appendWarning(warnings []string, warning string) []string {
	if len(warnings) >= 10 {
		return warnings
	}
	for _, existing := range warnings {
		if existing == warning {
			return warnings
		}
	}
	return append(warnings, warning)
}

func versionLessThan(a, b string) bool {
	parse := func(value string) []int {
		parts := strings.Split(value, ".")
		result := make([]int, len(parts))
		for index, part := range parts {
			for _, character := range part {
				if character < '0' || character > '9' {
					break
				}
				result[index] = result[index]*10 + int(character-'0')
			}
		}
		return result
	}
	left, right := parse(a), parse(b)
	for index := 0; index < max(len(left), len(right)); index++ {
		var l, r int
		if index < len(left) {
			l = left[index]
		}
		if index < len(right) {
			r = right[index]
		}
		if l != r {
			return l < r
		}
	}
	return false
}
