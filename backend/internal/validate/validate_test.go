package validate

import (
	"testing"

	"trivy/backend/internal/model"
)

func boolValue(value bool) *bool { return &value }

func TestRequestRequiresConsentForActiveScans(t *testing.T) {
	req := model.ScanRequest{Target: "https://example.com/", ScanMode: "active", Findings: []model.Finding{}}
	if _, err := Request(&req, 10, 5); err == nil {
		t.Fatal("expected consent error")
	}
}

func TestFindingRecomputesMixedContentSeverity(t *testing.T) {
	finding := model.Finding{
		Category: "mixed_content", PageURL: "https://example.com/", ResourceURL: "http://cdn.example.com/a.js",
		ResourceType: "script", Severity: model.SeverityLow,
	}
	if err := Finding(&finding); err != nil {
		t.Fatal(err)
	}
	if finding.Severity != model.SeverityHigh {
		t.Fatalf("severity = %q, want High", finding.Severity)
	}
}

func TestSensitiveURLMustBeRedacted(t *testing.T) {
	finding := model.Finding{
		Category: "sensitive_url", PageURL: "https://example.com/", URL: "https://example.com/?token=secret",
		ParameterName: "token", MatchReason: "token", Severity: model.SeverityHigh,
	}
	if err := Finding(&finding); err == nil {
		t.Fatal("expected unredacted URL to be rejected")
	}
}

func TestDeduplicate(t *testing.T) {
	finding := model.Finding{Category: "header", PageURL: "https://example.com/", Header: "content-security-policy", Status: "missing", Severity: model.SeverityMedium}
	if got := len(Deduplicate([]model.Finding{finding, finding})); got != 1 {
		t.Fatalf("deduplicated count = %d, want 1", got)
	}
}

func TestDeduplicateCollapsesRepeatedHeaderAcrossPages(t *testing.T) {
	first := model.Finding{Category: "header", PageURL: "https://example.com/", Header: "content-security-policy", Status: "missing", Severity: model.SeverityMedium}
	second := first
	second.PageURL = "https://example.com/api"
	result := Deduplicate([]model.Finding{first, second})
	if got := len(result); got != 1 {
		t.Fatalf("deduplicated count = %d, want one origin-wide header finding", got)
	}
	if result[0].AffectedPages != 2 || len(result[0].SampleURLs) != 2 {
		t.Fatalf("merged finding = %#v, want two affected pages and samples", result[0])
	}
}

func TestFindingReclassifiesCookieAndHeaderSeverity(t *testing.T) {
	missing := true
	notMissing := false
	cookie := model.Finding{
		Category: "insecure_cookie", PageURL: "https://example.com/", Severity: model.SeverityHigh,
		CookieName: "language", MissingSecure: &missing, MissingHTTPOnly: &missing, MissingSameSite: &notMissing,
	}
	if err := Finding(&cookie); err != nil {
		t.Fatal(err)
	}
	if cookie.Severity != model.SeverityLow {
		t.Fatalf("language cookie severity = %s, want Low", cookie.Severity)
	}

	header := model.Finding{
		Category: "header", PageURL: "https://example.com/", Severity: model.SeverityHigh,
		Header: "Referrer-Policy", Status: "missing",
	}
	if err := Finding(&header); err != nil {
		t.Fatal(err)
	}
	if header.Severity != model.SeverityInfo {
		t.Fatalf("Referrer-Policy severity = %s, want Info", header.Severity)
	}
}

func TestDeduplicateIgnoresFragmentAndSeverity(t *testing.T) {
	findings := []model.Finding{
		{Category: "header", PageURL: "https://example.com/#/", Header: "content-security-policy", Status: "missing", Severity: model.SeverityLow},
		{Category: "header", PageURL: "https://example.com/", Header: "content-security-policy", Status: "missing", Severity: model.SeverityMedium},
	}
	got := Deduplicate(findings)
	if len(got) != 1 || got[0].AffectedPages != 1 || got[0].Severity != model.SeverityMedium {
		t.Fatalf("deduplicated findings = %#v", got)
	}
}

func TestFindingValidatesBooleanPresence(t *testing.T) {
	finding := model.Finding{Category: "unencrypted_credentials", PageURL: "https://example.com/", FormAction: "http://example.com/login", Severity: model.SeverityLow, HasPasswordField: boolValue(true)}
	if err := Finding(&finding); err == nil {
		t.Fatal("expected missing isHttp to be rejected")
	}
}
