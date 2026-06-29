package selectel

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// captureLogger returns a *log.Logger that writes to buf with no flags so the
// output is predictable in assertions.
func captureLogger(buf *bytes.Buffer) Logger {
	return log.New(buf, "", 0)
}

// logLines splits buf into non-empty lines.
func logLines(buf *bytes.Buffer) []string {
	raw := strings.Split(buf.String(), "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// ----- normalizeZone --------------------------------------------------------

func TestNormalizeZone(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		{"zone.com", "zone.com."},
		{"zone.com.", "zone.com."},
		{"ZONE.COM", "zone.com."},
		{"ZONE.COM.", "zone.com."},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := normalizeZone(tc.in); got != tc.want {
				t.Fatalf("normalizeZone(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ----- recordFQDN -----------------------------------------------------------

func TestRecordFQDN(t *testing.T) {
	t.Parallel()

	zone := "zone.com."
	cases := []struct {
		name string
		want string
	}{
		{"host", "host.zone.com."},
		{"host.zone.com.", "host.zone.com."},
		{"@", "zone.com."},
		{"", "zone.com."},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"|"+tc.want, func(t *testing.T) {
			t.Parallel()
			got := recordFQDN(tc.name, zone)
			if got != tc.want {
				t.Fatalf("recordFQDN(%q, %q) = %q, want %q", tc.name, zone, got, tc.want)
			}
		})
	}
}

// ----- clampTTL -------------------------------------------------------------

func TestClampTTL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, want int
	}{
		{0, cMinTTL},
		{30, cMinTTL},
		{60, 60},
		{3600, 3600},
		{cMaxTTL, cMaxTTL},
		{cMaxTTL + 1, cMaxTTL},
		{999999, cMaxTTL},
	}

	for _, tc := range cases {
		tc := tc
		t.Run("", func(t *testing.T) {
			t.Parallel()
			if got := clampTTL(tc.in); got != tc.want {
				t.Fatalf("clampTTL(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// ----- TXT content conversion -----------------------------------------------

func TestContentToData_TXT(t *testing.T) {
	t.Parallel()

	cases := []struct {
		content, want string
	}{
		{`"hello world"`, "hello world"},
		{`""`, ""},
		{`"v=spf1 include:example.com ~all"`, "v=spf1 include:example.com ~all"},
		{"no quotes", "no quotes"}, // fallback: not quoted
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.content, func(t *testing.T) {
			t.Parallel()
			got := contentToData("TXT", tc.content)
			if got != tc.want {
				t.Fatalf("contentToData(TXT, %q) = %q, want %q", tc.content, got, tc.want)
			}
		})
	}
}

func TestDataToContent_TXT(t *testing.T) {
	t.Parallel()

	cases := []struct {
		data, want string
	}{
		{"hello world", `"hello world"`},
		{"", `""`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.data, func(t *testing.T) {
			t.Parallel()
			got := dataToContent("TXT", tc.data)
			if got != tc.want {
				t.Fatalf("dataToContent(TXT, %q) = %q, want %q", tc.data, got, tc.want)
			}
		})
	}
}

func TestContentToData_NonTXT(t *testing.T) {
	t.Parallel()

	if got := contentToData("A", "1.2.3.4"); got != "1.2.3.4" {
		t.Fatalf("expected pass-through, got %q", got)
	}
}

// ----- groupByNameType ------------------------------------------------------

func TestGroupByNameType_Basic(t *testing.T) {
	t.Parallel()

	zone := "zone.com."
	records := []libdns.Record{
		libdns.RR{Type: "A", Name: "host", Data: "1.2.3.1", TTL: 300 * time.Second},
		libdns.RR{Type: "A", Name: "host", Data: "1.2.3.2", TTL: 300 * time.Second},
		libdns.RR{Type: "TXT", Name: "host", Data: "hello", TTL: 60 * time.Second},
	}

	groups := groupByNameType(zone, records)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	if groups[0].typ != "A" || len(groups[0].items) != 2 {
		t.Fatalf("first group: want A with 2 items, got %s with %d items", groups[0].typ, len(groups[0].items))
	}

	if groups[1].typ != "TXT" || len(groups[1].items) != 1 {
		t.Fatalf("second group: want TXT with 1 item, got %s with %d items", groups[1].typ, len(groups[1].items))
	}
}

func TestGroupByNameType_TTLClamped(t *testing.T) {
	t.Parallel()

	zone := "zone.com."
	records := []libdns.Record{
		libdns.RR{Type: "A", Name: "host", Data: "1.2.3.4", TTL: 0},
	}

	groups := groupByNameType(zone, records)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].ttl != cMinTTL {
		t.Fatalf("expected TTL clamped to %d, got %d", cMinTTL, groups[0].ttl)
	}
}

func TestGroupByNameType_TXTContentQuoted(t *testing.T) {
	t.Parallel()

	zone := "zone.com."
	records := []libdns.Record{
		libdns.RR{Type: "TXT", Name: "host", Data: "v=spf1 all", TTL: 60 * time.Second},
	}

	groups := groupByNameType(zone, records)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}

	want := `"v=spf1 all"`
	if groups[0].items[0].Content != want {
		t.Fatalf("TXT content = %q, want %q", groups[0].items[0].Content, want)
	}
}

// ----- shouldRetry ----------------------------------------------------------

func TestShouldRetry(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		code int
		want bool
	}{
		{"429 retried", &httpError{StatusCode: 429}, 429, true},
		{"500 retried", &httpError{StatusCode: 500}, 500, true},
		{"502 retried", &httpError{StatusCode: 502}, 502, true},
		{"503 retried", &httpError{StatusCode: 503}, 503, true},
		{"504 retried", &httpError{StatusCode: 504}, 504, true},
		{"400 not retried", &httpError{StatusCode: 400}, 400, false},
		{"409 not retried", &httpError{StatusCode: 409}, 409, false},
		{"401 not retried via shouldRetry", &httpError{StatusCode: 401}, 401, false},
		{"net timeout retried", netTimeout{}, 0, true},
		{"EOF retried", io.EOF, 0, true},
		{"unexpected EOF retried", io.ErrUnexpectedEOF, 0, true},
		{"net.OpError retried", &net.OpError{Op: "dial", Err: errors.New("refused")}, 0, true},
		{"unknown not retried", errors.New("unknown error"), 0, false},
		{"nil with zero code", nil, 0, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := shouldRetry(tc.err, tc.code)
			if got != tc.want {
				t.Fatalf("shouldRetry(%v, %d) = %v, want %v", tc.err, tc.code, got, tc.want)
			}
		})
	}
}

// netTimeout is a fake net.Error that reports Timeout() == true.
type netTimeout struct{}

func (netTimeout) Error() string   { return "timeout" }
func (netTimeout) Timeout() bool   { return true }
func (netTimeout) Temporary() bool { return true }

// Ensure netTimeout satisfies net.Error.
var _ net.Error = netTimeout{}

// ----- Retry configuration --------------------------------------------------

func TestEffectiveRetryConfig_ZeroUsesDefaults(t *testing.T) {
	t.Parallel()

	p := &Provider{}
	got := p.effectiveRetryConfig()
	want := CreateDefaultHTTPRequestRetryConfiguration()
	if got != want {
		t.Fatalf("zero config did not produce defaults: got %+v, want %+v", got, want)
	}
}

func TestEffectiveRetryConfig_CustomHonoured(t *testing.T) {
	t.Parallel()

	custom := HTTPRequestRetryConfiguration{
		MaximumRetryAttempts:         0,
		InitialRetryDelay:            500 * time.Millisecond,
		MaximumRetryDelay:            time.Second,
		ExponentialBackoffMultiplier: 1.0,
	}
	p := &Provider{HTTPRequestRetryConfiguration: custom}
	if got := p.effectiveRetryConfig(); got != custom {
		t.Fatalf("custom config overridden: got %+v, want %+v", got, custom)
	}
}

func TestBackoffDelay_RespectsCap(t *testing.T) {
	t.Parallel()

	p := &Provider{}
	cfg := HTTPRequestRetryConfiguration{
		MaximumRetryAttempts:         5,
		InitialRetryDelay:            1 * time.Second,
		MaximumRetryDelay:            4 * time.Second,
		ExponentialBackoffMultiplier: 2.0,
	}

	check := func(attempt int, want time.Duration) {
		t.Helper()
		if got := p.backoffDelay(cfg, attempt); got != want {
			t.Fatalf("backoffDelay(attempt=%d) = %v, want %v", attempt, got, want)
		}
	}

	check(0, 1*time.Second)
	check(1, 2*time.Second)
	check(2, 4*time.Second)
	check(3, 4*time.Second) // capped
}

// ----- httpError ------------------------------------------------------------

func TestHTTPError_Message(t *testing.T) {
	t.Parallel()

	e := &httpError{StatusCode: http.StatusUnprocessableEntity, Status: "Unprocessable Entity", Message: "invalid ttl"}
	if !strings.Contains(e.Error(), "422") {
		t.Fatalf("error string missing status code: %q", e.Error())
	}
	if !strings.Contains(e.Error(), "invalid ttl") {
		t.Fatalf("error string missing message: %q", e.Error())
	}
}

func TestHTTPError_Unauthorized(t *testing.T) {
	t.Parallel()

	e := &httpError{StatusCode: http.StatusUnauthorized}
	if !e.isUnauthorized() {
		t.Fatal("expected isUnauthorized() == true for 401")
	}

	e2 := &httpError{StatusCode: http.StatusNotFound}
	if e2.isUnauthorized() {
		t.Fatal("expected isUnauthorized() == false for 404")
	}
}

// ----- Logging --------------------------------------------------------------

func TestLogDebug_RespectsFlag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &Provider{Logger: captureLogger(&buf), EnableDebugLogging: false}

	p.logDebug("OP", "should not appear")
	if lines := logLines(&buf); len(lines) != 0 {
		t.Fatalf("expected no DEBUG output when flag is off, got %v", lines)
	}

	p.EnableDebugLogging = true
	// logOnce may have already run (from logInfo/logError calls), but since
	// Logger was set before any call, activeLogger is already p.Logger.
	// For this test, call emit directly to bypass the logOnce caching issue
	// when we change EnableDebugLogging after the logger was initialised.
	// Instead, create a fresh provider:
	var buf2 bytes.Buffer
	p2 := &Provider{Logger: captureLogger(&buf2), EnableDebugLogging: true}
	p2.logDebug("OP", "should appear")

	lines := logLines(&buf2)
	if len(lines) != 1 {
		t.Fatalf("expected 1 DEBUG line, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "[DEBUG]") {
		t.Fatalf("missing [DEBUG] tag: %q", lines[0])
	}
}

func TestLogInfoAndError_AlwaysEmit(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	p := &Provider{Logger: captureLogger(&buf), EnableDebugLogging: false}

	p.logInfo("OP", "info message")
	p.logError("OP", "error message")

	lines := logLines(&buf)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (INFO + ERROR), got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "[INFO]") {
		t.Fatalf("first line missing [INFO]: %q", lines[0])
	}
	if !strings.Contains(lines[1], "[ERROR]") {
		t.Fatalf("second line missing [ERROR]: %q", lines[1])
	}
}

func TestLog_NilLoggerIsNoOp(t *testing.T) {
	t.Parallel()

	p := &Provider{EnableDebugLogging: false}
	// Must not panic with a nil logger and debug disabled.
	p.logDebug("OP", "msg")
	p.logInfo("OP", "msg")
	p.logError("OP", "msg")
}

// ----- buildHTTPError -------------------------------------------------------

func TestBuildHTTPError_StructuredBody(t *testing.T) {
	t.Parallel()

	body := []byte(`{"error":"invalid_request","description":"TTL out of range","location":"ttl"}`)
	e := buildHTTPError(http.StatusUnprocessableEntity, body)
	if e.Message != "TTL out of range" {
		t.Fatalf("expected description in message, got %q", e.Message)
	}
}

func TestBuildHTTPError_FallbackRawBody(t *testing.T) {
	t.Parallel()

	body := []byte("plain text error")
	e := buildHTTPError(http.StatusInternalServerError, body)
	if !strings.Contains(e.Message, "plain text error") {
		t.Fatalf("expected raw body in message, got %q", e.Message)
	}
}

func TestBuildHTTPError_EmptyBody(t *testing.T) {
	t.Parallel()

	e := buildHTTPError(http.StatusNotFound, nil)
	if e.Message != "" {
		t.Fatalf("expected empty message for nil body, got %q", e.Message)
	}
	if !strings.Contains(e.Error(), "404") {
		t.Fatalf("error string missing status code: %q", e.Error())
	}
}
