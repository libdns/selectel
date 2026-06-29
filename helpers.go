package selectel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// ----- Name helpers ---------------------------------------------------------

// normalizeZone returns zone as a lower-case FQDN with a trailing dot.
func normalizeZone(zone string) string {
	zone = strings.ToLower(strings.TrimSpace(zone))
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	return zone
}

// ensureTrailingDot returns s with a trailing dot appended if missing.
func ensureTrailingDot(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// recordFQDN returns the FQDN (with trailing dot) for a libdns record name
// relative to zone. Zone must already be normalised (trailing dot).
func recordFQDN(name, zone string) string {
	return strings.ToLower(libdns.AbsoluteName(name, zone))
}

// recordRelName returns the record name relative to zone (no trailing dot).
// Zone must already be normalised (trailing dot).
func recordRelName(fqdn, zone string) string {
	rel := libdns.RelativeName(fqdn, zone)
	if rel == "" {
		return "@"
	}
	return rel
}

// ----- TTL helpers ----------------------------------------------------------

// clampTTL returns ttl clamped to the Selectel-accepted range [cMinTTL, cMaxTTL].
func clampTTL(ttl int) int {
	if ttl < cMinTTL {
		return cMinTTL
	}
	if ttl > cMaxTTL {
		return cMaxTTL
	}
	return ttl
}

// ----- Content / Data conversion --------------------------------------------

// contentToData converts a Selectel API content string to the libdns RR Data
// field. For TXT records the API wraps values in double quotes; we strip them.
func contentToData(recType, content string) string {
	if recType == "TXT" {
		return stripTXTQuotes(content)
	}
	return content
}

// dataToContent converts a libdns RR Data field to the Selectel API content
// string. TXT values are wrapped in double quotes as the API requires.
func dataToContent(recType, data string) string {
	if recType == "TXT" {
		return `"` + data + `"`
	}
	return data
}

// stripTXTQuotes removes the outer pair of double quotes from a TXT content
// value. If the string is not quoted, it is returned unchanged.
func stripTXTQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ----- Record conversion ----------------------------------------------------

// apiRecordToLibdns expands a Selectel RRset into individual libdns.Record
// values — one per RecordItem. Zone must already be normalised.
func apiRecordToLibdns(zone string, r Record) []libdns.Record {
	ttl := time.Duration(r.TTL) * time.Second
	fqdn := ensureTrailingDot(strings.ToLower(r.Name))
	rel := recordRelName(fqdn, zone)

	out := make([]libdns.Record, 0, len(r.Records))
	for _, item := range r.Records {
		if item.Disabled {
			continue
		}
		data := contentToData(r.Type, item.Content)
		rr := libdns.RR{Name: rel, TTL: ttl, Type: r.Type, Data: data}
		parsed, err := rr.Parse()
		if err != nil {
			out = append(out, rr)
		} else {
			out = append(out, parsed)
		}
	}
	return out
}

// ----- RRset grouping -------------------------------------------------------

// rrGroup represents one (name, type) RRset worth of input records for
// Append / Set operations.
type rrGroup struct {
	fqdn    string       // FQDN with trailing dot
	typ     string       // e.g. "A", "TXT"
	ttl     int          // clamped TTL
	items   []RecordItem // values to write to the API
	srcRecs []libdns.Record
}

// groupByNameType partitions records into rrGroups keyed by (FQDN, type).
// Ordering of groups follows first occurrence in the input. Zone must
// already be normalised.
func groupByNameType(zone string, records []libdns.Record) []rrGroup {
	type key struct{ fqdn, typ string }
	var order []key
	groups := map[key]*rrGroup{}

	for _, r := range records {
		rr := r.RR()
		fqdn := recordFQDN(rr.Name, zone)
		typ := strings.ToUpper(rr.Type)
		k := key{fqdn, typ}

		g, ok := groups[k]
		if !ok {
			g = &rrGroup{fqdn: fqdn, typ: typ}
			groups[k] = g
			order = append(order, k)
		}

		ttl := clampTTL(int(rr.TTL.Seconds()))
		if g.ttl == 0 {
			g.ttl = ttl
		}

		if rr.Data != "" {
			g.items = append(g.items, RecordItem{Content: dataToContent(typ, rr.Data)})
			g.srcRecs = append(g.srcRecs, r)
		}
	}

	result := make([]rrGroup, 0, len(order))
	for _, k := range order {
		result = append(result, *groups[k])
	}
	return result
}

// ----- Zone ID resolution ---------------------------------------------------

// getZoneID returns the Selectel zone ID for zone, using the cache when
// available and fetching from the API otherwise. Zone must already be
// normalised (lower-case, trailing dot).
func (p *Provider) getZoneID(ctx context.Context, zone string) (string, error) {
	nz := normalizeZone(zone)

	p.cacheMu.RLock()
	id := p.zoneCache[nz]
	p.cacheMu.RUnlock()

	if id != "" {
		p.logDebug("GET_ZONE_ID", "Zone %q found in cache: %s", nz, id)
		return id, nil
	}

	p.logDebug("GET_ZONE_ID", "Fetching zone ID for %q from API", nz)

	var offset int
	for {
		apiURL := p.getAPIBase() + "/zones?" + url.Values{
			"filter": {nz},
			"limit":  {strconv.Itoa(cPageSize)},
			"offset": {strconv.Itoa(offset)},
		}.Encode()

		data, err := p.makeAPIRequest(ctx, httpGET, apiURL, nil)
		if err != nil {
			p.logError("GET_ZONE_ID", "API error for zone %q: %v", nz, err)
			return "", fmt.Errorf("get zone %q: %w", nz, err)
		}

		var page paginatedZones
		if err := json.Unmarshal(data, &page); err != nil {
			return "", fmt.Errorf("unmarshal zones: %w", err)
		}

		for _, z := range page.Result {
			// Exact FQDN match (case-insensitive).
			if strings.EqualFold(ensureTrailingDot(z.Name), nz) {
				p.logInfo("GET_ZONE_ID", "Resolved zone %q → ID %s", nz, z.ID)
				p.cacheMu.Lock()
				if p.zoneCache == nil {
					p.zoneCache = make(map[string]string)
				}
				p.zoneCache[nz] = z.ID
				p.cacheMu.Unlock()
				return z.ID, nil
			}
		}

		if page.NextOffset <= 0 || len(page.Result) == 0 {
			break
		}
		offset = page.NextOffset
	}

	p.logError("GET_ZONE_ID", "Zone %q not found", nz)
	return "", fmt.Errorf("zone %q not found in Selectel account", nz)
}

// ----- RRset API helpers ----------------------------------------------------

// listAllRRsets returns every RRset in the zone using pagination.
func (p *Provider) listAllRRsets(ctx context.Context, zoneID string) ([]Record, error) {
	return p.listRRsetsPaged(ctx, zoneID, nil)
}

// getRRset fetches a single RRset by (FQDN, type). Returns nil, nil when the
// RRset does not exist. fqdn must be a FQDN with a trailing dot.
func (p *Provider) getRRset(ctx context.Context, zoneID, fqdn, rrType string) (*Record, error) {
	params := url.Values{
		"name":        {fqdn},
		"rrset_types": {rrType},
	}
	rrsets, err := p.listRRsetsPaged(ctx, zoneID, params)
	if err != nil {
		return nil, err
	}
	if len(rrsets) == 0 {
		return nil, nil
	}
	return &rrsets[0], nil
}

// listRRsetsAtName returns all RRsets (any type) for a given FQDN.
func (p *Provider) listRRsetsAtName(ctx context.Context, zoneID, fqdn string) ([]Record, error) {
	return p.listRRsetsPaged(ctx, zoneID, url.Values{"name": {fqdn}})
}

// listRRsetsPaged fetches all RRsets for a zone using cursor-based pagination,
// merging optional extra query params. zoneID is the Selectel zone UUID.
func (p *Provider) listRRsetsPaged(ctx context.Context, zoneID string, extraParams url.Values) ([]Record, error) {
	var all []Record

	for offset := 0; ; {
		qp := url.Values{
			"limit":  {strconv.Itoa(cPageSize)},
			"offset": {strconv.Itoa(offset)},
		}
		for k, v := range extraParams {
			qp[k] = v
		}

		apiURL := p.getAPIBase() + fmt.Sprintf("/zones/%s/rrset?", zoneID) + qp.Encode()
		data, err := p.makeAPIRequest(ctx, httpGET, apiURL, nil)
		if err != nil {
			return nil, err
		}

		var page paginatedRRsets
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("unmarshal rrsets: %w", err)
		}

		all = append(all, page.Result...)

		if page.NextOffset <= 0 || len(all) >= page.Count {
			break
		}
		offset = page.NextOffset
	}

	return all, nil
}

// createRRset issues POST /zones/{zoneID}/rrset and returns the newly created
// records as libdns values. zone must already be normalised.
func (p *Provider) createRRset(ctx context.Context, zoneID, zone string, grp rrGroup) ([]libdns.Record, error) {
	p.logDebug("CREATE_RRSET", "Creating %s RRset %q in zone %s (TTL %d, %d values)",
		grp.typ, grp.fqdn, zone, grp.ttl, len(grp.items))

	payload := rrsetCreatePayload{
		Name:    grp.fqdn,
		TTL:     grp.ttl,
		Type:    grp.typ,
		Records: grp.items,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal create payload: %w", err)
	}

	apiURL := p.getAPIBase() + fmt.Sprintf("/zones/%s/rrset", zoneID)
	if _, err := p.makeAPIRequest(ctx, httpPOST, apiURL, body); err != nil {
		p.logError("CREATE_RRSET", "Failed to create RRset %q/%s: %v", grp.fqdn, grp.typ, err)
		return nil, fmt.Errorf("create rrset %s/%s: %w", grp.fqdn, grp.typ, err)
	}

	p.logInfo("CREATE_RRSET", "Created %s RRset %q", grp.typ, grp.fqdn)
	return grp.srcRecs, nil
}

// patchRRset issues PATCH /zones/{zoneID}/rrset/{rrsetID}.
func (p *Provider) patchRRset(ctx context.Context, zoneID, rrsetID string, payload rrsetUpdatePayload) error {
	p.logDebug("PATCH_RRSET", "Patching RRset %s (TTL %d, %d values)", rrsetID, payload.TTL, len(payload.Records))

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal patch payload: %w", err)
	}

	apiURL := p.getAPIBase() + fmt.Sprintf("/zones/%s/rrset/%s", zoneID, rrsetID)
	if _, err := p.makeAPIRequest(ctx, httpPATCH, apiURL, body); err != nil {
		p.logError("PATCH_RRSET", "Failed to patch RRset %s: %v", rrsetID, err)
		return fmt.Errorf("patch rrset %s: %w", rrsetID, err)
	}

	p.logInfo("PATCH_RRSET", "Patched RRset %s", rrsetID)
	return nil
}

// deleteRRset issues DELETE /zones/{zoneID}/rrset/{rrsetID}.
func (p *Provider) deleteRRset(ctx context.Context, zoneID, rrsetID string) error {
	p.logDebug("DELETE_RRSET", "Deleting RRset %s", rrsetID)

	apiURL := p.getAPIBase() + fmt.Sprintf("/zones/%s/rrset/%s", zoneID, rrsetID)
	if _, err := p.makeAPIRequest(ctx, httpDELETE, apiURL, nil); err != nil {
		p.logError("DELETE_RRSET", "Failed to delete RRset %s: %v", rrsetID, err)
		return fmt.Errorf("delete rrset %s: %w", rrsetID, err)
	}

	p.logInfo("DELETE_RRSET", "Deleted RRset %s", rrsetID)
	return nil
}

// ----- HTTP layer -----------------------------------------------------------

// makeAPIRequest issues an authenticated, retried API request and returns the
// raw response body. body may be nil.
func (p *Provider) makeAPIRequest(ctx context.Context, method, apiURL string, body []byte) ([]byte, error) {
	p.logDebug("HTTP", "→ %s %s", method, apiURL)
	return p.executeWithRetry(ctx, method, apiURL, body)
}

// executeWithRetry runs the request with retry logic for transient errors and
// automatic token refresh on 401.
func (p *Provider) executeWithRetry(ctx context.Context, method, apiURL string, body []byte) ([]byte, error) {
	cfg := p.effectiveRetryConfig()
	var lastErr error
	retries := 0
	reAuthed := false

	for {
		staleToken := p.currentToken()

		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}

		data, err := p.executeSingleRequest(ctx, method, apiURL, bodyReader, staleToken)
		if err == nil {
			if retries > 0 {
				p.logInfo("HTTP", "Request succeeded on attempt %d", retries+1)
			}
			return data, nil
		}

		lastErr = err
		p.logError("HTTP", "Attempt %d failed: %v", retries+1, err)

		// On 401: re-authenticate once, then retry immediately.
		var httpErr *httpError
		if errors.As(err, &httpErr) && httpErr.isUnauthorized() && !reAuthed {
			reAuthed = true
			p.logDebug("HTTP", "401 received — re-authenticating")
			if authErr := p.ensureTokenNotStale(ctx, staleToken); authErr != nil {
				p.logError("HTTP", "Re-authentication failed: %v", authErr)
				return nil, authErr
			}
			continue // retry without counting as a regular retry
		}

		// Check retry eligibility.
		if retries >= cfg.MaximumRetryAttempts {
			break
		}
		sc := 0
		if errors.As(err, &httpErr) {
			sc = httpErr.StatusCode
		}
		if !shouldRetry(err, sc) {
			p.logDebug("HTTP", "Error is not retryable")
			break
		}

		retries++
		backoff := p.backoffDelay(cfg, retries-1)
		p.logDebug("HTTP", "Retry %d/%d after %v", retries, cfg.MaximumRetryAttempts, backoff)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}

	return nil, fmt.Errorf("request failed after %d attempt(s): %w", retries+1, lastErr)
}

// executeSingleRequest performs one HTTP round-trip. Non-2xx responses are
// returned as *httpError so callers can inspect the status code.
func (p *Provider) executeSingleRequest(ctx context.Context, method, apiURL string, body io.Reader, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, apiURL, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", cUserAgent)

	resp, err := p.sharedClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, cResponseBodyLimit))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, buildHTTPError(resp.StatusCode, respBody)
	}

	return respBody, nil
}

// buildHTTPError constructs an *httpError, parsing the Selectel structured
// error body when possible and falling back to a raw body excerpt.
func buildHTTPError(statusCode int, body []byte) *httpError {
	e := &httpError{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
	}

	var apiErr apiErrorBody
	if json.Unmarshal(body, &apiErr) == nil {
		if apiErr.Description != "" {
			e.Message = apiErr.Description
			return e
		}
		if apiErr.Error != "" {
			e.Message = apiErr.Error
			return e
		}
	}

	if len(body) > 0 {
		excerpt := string(body)
		if len(excerpt) > 200 {
			excerpt = excerpt[:200] + "…"
		}
		e.Message = excerpt
	}

	return e
}

// shouldRetry reports whether a failed request should be retried.
func shouldRetry(err error, statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}

	if err == nil {
		return false
	}

	// Never retry context cancellation or deadline.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Network-level timeout.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Unexpected EOF / connection reset.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// Generic network operation failure (includes connection refused, DNS failure).
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	return false
}

// ----- Retry helpers --------------------------------------------------------

func (p *Provider) effectiveRetryConfig() HTTPRequestRetryConfiguration {
	if p.HTTPRequestRetryConfiguration == (HTTPRequestRetryConfiguration{}) {
		return CreateDefaultHTTPRequestRetryConfiguration()
	}
	return p.HTTPRequestRetryConfiguration
}

func (p *Provider) backoffDelay(cfg HTTPRequestRetryConfiguration, attempt int) time.Duration {
	d := time.Duration(float64(cfg.InitialRetryDelay) * math.Pow(cfg.ExponentialBackoffMultiplier, float64(attempt)))
	if d > cfg.MaximumRetryDelay {
		d = cfg.MaximumRetryDelay
	}
	return d
}
