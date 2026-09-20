package model

import "time"

type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
)

type RateLimit struct {
	RequestsPerSecond int `json:"requestsPerSecond"`
	MaxConcurrency    int `json:"maxConcurrency"`
}

type Finding struct {
	Category      string   `json:"category"`
	PageURL       string   `json:"pageUrl"`
	Severity      Severity `json:"severity"`
	Confidence    string   `json:"confidence,omitempty"`
	Source        string   `json:"source,omitempty"`
	Evidence      string   `json:"evidence,omitempty"`
	TestedURL     string   `json:"testedUrl,omitempty"`
	AffectedPages int      `json:"affectedPages,omitempty"`
	SampleURLs    []string `json:"sampleUrls,omitempty"`

	Header string  `json:"header,omitempty"`
	Value  *string `json:"value,omitempty"`
	Status string  `json:"status,omitempty"`

	FormAction              string `json:"formAction,omitempty"`
	Method                  string `json:"method,omitempty"`
	HasPasswordField        *bool  `json:"hasPasswordField,omitempty"`
	IsActionInsecure        *bool  `json:"isActionInsecure,omitempty"`
	AutocompleteOnSensitive *bool  `json:"autocompleteOnSensitive,omitempty"`
	HasCSRFToken            *bool  `json:"hasCsrfToken,omitempty"`
	IsHTTP                  *bool  `json:"isHttp,omitempty"`

	ResourceURL   string `json:"resourceUrl,omitempty"`
	ResourceType  string `json:"resourceType,omitempty"`
	URL           string `json:"url,omitempty"`
	ParameterName string `json:"parameterName,omitempty"`
	MatchReason   string `json:"matchReason,omitempty"`

	CookieName      string `json:"cookieName,omitempty"`
	MissingSecure   *bool  `json:"missingSecure,omitempty"`
	MissingHTTPOnly *bool  `json:"missingHttpOnly,omitempty"`
	MissingSameSite *bool  `json:"missingSameSite,omitempty"`

	SecretType      string `json:"secretType,omitempty"`
	Location        string `json:"location,omitempty"`
	LibraryName     string `json:"libraryName,omitempty"`
	DetectedVersion string `json:"detectedVersion,omitempty"`
	KnownCVE        string `json:"knownCve,omitempty"`
	StorageType     string `json:"storageType,omitempty"`
	KeyName         string `json:"keyName,omitempty"`
	Reason          string `json:"reason,omitempty"`

	MarkerValue        string `json:"markerValue,omitempty"`
	EvidenceSnippet    string `json:"evidenceSnippet,omitempty"`
	RequestOrigin      string `json:"requestOrigin,omitempty"`
	ReflectedACAOValue string `json:"reflectedAcaoValue,omitempty"`
	AllowsCredentials  *bool  `json:"allowsCredentials,omitempty"`
}

type ScanRequest struct {
	Target        string     `json:"target"`
	ScanMode      string     `json:"scanMode"`
	Consent       bool       `json:"consent"`
	Findings      []Finding  `json:"findings"`
	RateLimit     *RateLimit `json:"rateLimit,omitempty"`
	ExcludedPaths []string   `json:"excludedPaths,omitempty"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type ScanResponse struct {
	ScanID   string    `json:"scanId"`
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
	Coverage *Coverage `json:"coverage,omitempty"`
}

type Coverage struct {
	PagesDiscovered  int      `json:"pagesDiscovered"`
	PagesScanned     int      `json:"pagesScanned"`
	RequestsMade     int      `json:"requestsMade"`
	FormsDiscovered  int      `json:"formsDiscovered"`
	ParametersTested int      `json:"parametersTested"`
	BodyParametersTested int  `json:"bodyParametersTested"`
	ActiveProbes      int      `json:"activeProbes"`
	Truncated        bool     `json:"truncated"`
	Warnings         []string `json:"warnings,omitempty"`
}

type StoredScan struct {
	ID        string
	Mode      string
	Target    string
	Response  ScanResponse
	CreatedAt time.Time
	ExpiresAt time.Time
}
