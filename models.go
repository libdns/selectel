package selectel

import (
	"fmt"
	"net/http"
	"time"
)

const (
	cAPIBaseURL          = "https://api.selectel.ru/domains/v2"
	cTokensURL           = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
	cKeystoneTokenHeader = "X-Subject-Token"
	cHTTPClientTimeout   = 30 * time.Second
	cMinTTL              = 60      // Selectel rejects TTL < 60
	cMaxTTL              = 604800  // Selectel rejects TTL > 604800
	cResponseBodyLimit   = 1 << 20 // 1 MiB cap on response bodies
	cTokenExpiryBuffer   = 5 * time.Minute
	cUserAgent           = "libdns-selectel"
	cPageSize            = 1000
)

// HTTP method constants.
const (
	httpGET    = http.MethodGet
	httpPOST   = http.MethodPost
	httpPATCH  = http.MethodPatch
	httpDELETE = http.MethodDelete
)

// Logger is the minimal logging interface consumed by Provider. It is satisfied
// by *log.Logger and by thin wrappers over structured loggers such as zap.
type Logger interface {
	Printf(format string, v ...any)
}

// HTTPRequestRetryConfiguration controls the exponential-backoff retry behaviour
// for transient HTTP failures.
//
// A zero-value (the default) means "use sensible defaults"; see
// CreateDefaultHTTPRequestRetryConfiguration. To disable retries, set
// MaximumRetryAttempts to 0 and any other field to a non-zero value
// (e.g. InitialRetryDelay: time.Second).
type HTTPRequestRetryConfiguration struct {
	// MaximumRetryAttempts is the number of retries after the initial attempt,
	// so the total number of attempts is MaximumRetryAttempts + 1.
	MaximumRetryAttempts int
	// InitialRetryDelay is the delay before the first retry.
	InitialRetryDelay time.Duration
	// MaximumRetryDelay caps the exponential backoff.
	MaximumRetryDelay time.Duration
	// ExponentialBackoffMultiplier scales the delay on each successive retry.
	ExponentialBackoffMultiplier float64
}

// CreateDefaultHTTPRequestRetryConfiguration returns a conservative policy:
// up to 3 retries with exponential backoff from 1 s to 30 s.
func CreateDefaultHTTPRequestRetryConfiguration() HTTPRequestRetryConfiguration {
	return HTTPRequestRetryConfiguration{
		MaximumRetryAttempts:         3,
		InitialRetryDelay:            1 * time.Second,
		MaximumRetryDelay:            30 * time.Second,
		ExponentialBackoffMultiplier: 2.0,
	}
}

// ----- Keystone auth request types ------------------------------------------

type keystoneAuthRequest struct {
	Auth keystoneAuth `json:"auth"`
}

type keystoneAuth struct {
	Identity keystoneIdentity `json:"identity"`
	Scope    keystoneScope    `json:"scope"`
}

type keystoneIdentity struct {
	Methods  []string         `json:"methods"`
	Password keystonePassword `json:"password"`
}

type keystonePassword struct {
	User keystoneUser `json:"user"`
}

type keystoneUser struct {
	Name     string         `json:"name"`
	Password string         `json:"password"`
	Domain   keystoneDomain `json:"domain"`
}

type keystoneDomain struct {
	Name string `json:"name"`
}

type keystoneScope struct {
	Project keystoneProject `json:"project"`
}

type keystoneProject struct {
	Name   string         `json:"name"`
	Domain keystoneDomain `json:"domain"`
}

// keystoneTokenResponse holds the subset of the Keystone auth response body
// that we need (token expiry).
type keystoneTokenResponse struct {
	Token struct {
		ExpiresAt string `json:"expires_at"`
	} `json:"token"`
}

// ----- API error types -------------------------------------------------------

// apiErrorBody is the structured error format returned by the Selectel DNS API.
type apiErrorBody struct {
	Error       string `json:"error"`
	Description string `json:"description"`
	Location    string `json:"location"`
}

// httpError represents a non-2xx HTTP response from the Selectel API.
// It is a concrete type so callers can use errors.As to inspect it.
type httpError struct {
	StatusCode int
	Status     string
	// Message is a human-readable description: the API's Description field
	// when parseable, otherwise a truncated excerpt of the raw response body.
	Message string
}

func (e *httpError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s (%d): %s", e.Status, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("%s (%d)", e.Status, e.StatusCode)
}

// isUnauthorized reports whether this is an HTTP 401 response.
func (e *httpError) isUnauthorized() bool { return e.StatusCode == http.StatusUnauthorized }

// ----- Selectel DNS API model types -----------------------------------------

// Zone is a Selectel DNS zone as returned by the API.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Record is a Selectel DNS RRset (resource record set).
type Record struct {
	ID      string       `json:"id,omitempty"`
	Type    string       `json:"type"`
	Name    string       `json:"name"`
	Records []RecordItem `json:"records"`
	TTL     int          `json:"ttl"`
}

// RecordItem is a single value within a Selectel RRset.
type RecordItem struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// ----- Paginated API response types -----------------------------------------

type paginatedZones struct {
	Count      int    `json:"count"`
	NextOffset int    `json:"next_offset"`
	Result     []Zone `json:"result"`
}

type paginatedRRsets struct {
	Count      int      `json:"count"`
	NextOffset int      `json:"next_offset"`
	Result     []Record `json:"result"`
}

// ----- API request payload types --------------------------------------------

// rrsetCreatePayload is the body for POST /zones/{id}/rrset.
type rrsetCreatePayload struct {
	Name    string       `json:"name"`
	TTL     int          `json:"ttl"`
	Type    string       `json:"type"`
	Records []RecordItem `json:"records"`
}

// rrsetUpdatePayload is the body for PATCH /zones/{id}/rrset/{id}.
// The Selectel API accepts only ttl, records, and comment; sending id/name/type
// may cause a 422.
type rrsetUpdatePayload struct {
	TTL     int          `json:"ttl"`
	Records []RecordItem `json:"records"`
	Comment string       `json:"comment,omitempty"`
}
