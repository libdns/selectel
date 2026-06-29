package selectel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// ----- Token management -----------------------------------------------------

// ensureToken guarantees that p.token is non-empty and not about to expire.
// It is safe for concurrent use.
func (p *Provider) ensureToken(ctx context.Context) error {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	if p.token != "" && time.Now().Add(cTokenExpiryBuffer).Before(p.tokenExpiry) {
		return nil
	}
	return p.authenticate(ctx)
}

// ensureTokenNotStale refreshes the token only when it still matches
// staleToken (the token used by a request that received a 401). If another
// goroutine already refreshed the token, the check short-circuits.
func (p *Provider) ensureTokenNotStale(ctx context.Context, staleToken string) error {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	// Another goroutine already refreshed the token.
	if p.token != "" && p.token != staleToken && time.Now().Add(cTokenExpiryBuffer).Before(p.tokenExpiry) {
		return nil
	}
	return p.authenticate(ctx)
}

// authenticate obtains a fresh Keystone IAM token.
// Callers must hold p.tokenMu.
func (p *Provider) authenticate(ctx context.Context) error {
	reqBody := keystoneAuthRequest{
		Auth: keystoneAuth{
			Identity: keystoneIdentity{
				Methods: []string{"password"},
				Password: keystonePassword{
					User: keystoneUser{
						Name:     p.User,
						Password: p.Password,
						Domain:   keystoneDomain{Name: p.AccountId},
					},
				},
			},
			Scope: keystoneScope{
				Project: keystoneProject{
					Name:   p.ProjectName,
					Domain: keystoneDomain{Name: p.AccountId},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, httpPOST, p.getTokenBase(), bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", cUserAgent)

	resp, err := p.sharedClient().Do(req)
	if err != nil {
		return fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, cResponseBodyLimit))
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return buildHTTPError(resp.StatusCode, respBody)
	}

	token := resp.Header.Get(cKeystoneTokenHeader)
	if token == "" {
		return fmt.Errorf("header %q missing in auth response", cKeystoneTokenHeader)
	}

	// Parse token expiry from the response body; fall back to 24 h.
	expiry := time.Now().Add(24 * time.Hour)
	var tokenResp keystoneTokenResponse
	if json.Unmarshal(respBody, &tokenResp) == nil && tokenResp.Token.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, tokenResp.Token.ExpiresAt); err == nil {
			expiry = t
		}
	}

	p.token = token
	p.tokenExpiry = expiry
	p.logDebug("AUTH", "Token obtained, expires %s", expiry.Format(time.RFC3339))
	return nil
}

// ----- GetRecords -----------------------------------------------------------

func (p *Provider) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, err
	}

	nz := normalizeZone(zone)
	zoneID, err := p.getZoneID(ctx, nz)
	if err != nil {
		return nil, err
	}

	p.logDebug("GET_RECORDS", "Listing all RRsets in zone %q (ID %s)", nz, zoneID)

	rrsets, err := p.listAllRRsets(ctx, zoneID)
	if err != nil {
		p.logError("GET_RECORDS", "Failed to list RRsets: %v", err)
		return nil, err
	}

	var out []libdns.Record
	for _, r := range rrsets {
		out = append(out, apiRecordToLibdns(nz, r)...)
	}

	p.logInfo("GET_RECORDS", "Returned %d records from zone %q", len(out), nz)
	return out, nil
}

// ----- AppendRecords --------------------------------------------------------

// appendRecords adds new values to each (name, type) RRset without modifying
// values that already exist. Only newly added records are returned.
func (p *Provider) appendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, err
	}

	nz := normalizeZone(zone)
	zoneID, err := p.getZoneID(ctx, nz)
	if err != nil {
		return nil, err
	}

	groups := groupByNameType(nz, records)
	p.logInfo("APPEND_RECORDS", "Appending %d group(s) to zone %q", len(groups), nz)

	var result []libdns.Record
	var lastErr error

	for _, grp := range groups {
		if len(grp.items) == 0 {
			continue
		}

		existing, err := p.getRRset(ctx, zoneID, grp.fqdn, grp.typ)
		if err != nil {
			p.logError("APPEND_RECORDS", "Failed to fetch RRset %q/%s: %v", grp.fqdn, grp.typ, err)
			lastErr = err
			continue
		}

		if existing == nil {
			// RRset does not exist yet — create it.
			created, err := p.createRRset(ctx, zoneID, nz, grp)
			if err != nil {
				lastErr = err
				continue
			}
			result = append(result, created...)
			continue
		}

		// RRset exists — add only values not already present.
		existingSet := make(map[string]bool, len(existing.Records))
		for _, item := range existing.Records {
			existingSet[item.Content] = true
		}

		var newItems []RecordItem
		var newSrc []libdns.Record
		for i, item := range grp.items {
			if !existingSet[item.Content] {
				newItems = append(newItems, item)
				newSrc = append(newSrc, grp.srcRecs[i])
			}
		}

		if len(newItems) == 0 {
			p.logDebug("APPEND_RECORDS", "All values for %q/%s already exist, nothing to add", grp.fqdn, grp.typ)
			continue
		}

		merged := append(existing.Records, newItems...) //nolint:gocritic // intentional copy
		// Keep the existing TTL to avoid modifying what was already there.
		patch := rrsetUpdatePayload{TTL: existing.TTL, Records: merged}
		if err := p.patchRRset(ctx, zoneID, existing.ID, patch); err != nil {
			lastErr = err
			continue
		}

		result = append(result, newSrc...)
		p.logInfo("APPEND_RECORDS", "Added %d value(s) to %q/%s", len(newItems), grp.fqdn, grp.typ)
	}

	return result, lastErr
}

// ----- SetRecords -----------------------------------------------------------

// setRecords replaces each (name, type) RRset with exactly the provided values.
func (p *Provider) setRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, err
	}

	nz := normalizeZone(zone)
	zoneID, err := p.getZoneID(ctx, nz)
	if err != nil {
		return nil, err
	}

	groups := groupByNameType(nz, records)
	p.logInfo("SET_RECORDS", "Setting %d group(s) in zone %q", len(groups), nz)

	var result []libdns.Record
	var lastErr error

	for _, grp := range groups {
		if len(grp.items) == 0 {
			continue
		}

		existing, err := p.getRRset(ctx, zoneID, grp.fqdn, grp.typ)
		if err != nil {
			p.logError("SET_RECORDS", "Failed to fetch RRset %q/%s: %v", grp.fqdn, grp.typ, err)
			lastErr = err
			continue
		}

		if existing == nil {
			created, err := p.createRRset(ctx, zoneID, nz, grp)
			if err != nil {
				lastErr = err
				continue
			}
			result = append(result, created...)
			continue
		}

		patch := rrsetUpdatePayload{TTL: grp.ttl, Records: grp.items}
		if err := p.patchRRset(ctx, zoneID, existing.ID, patch); err != nil {
			lastErr = err
			continue
		}

		result = append(result, grp.srcRecs...)
		p.logInfo("SET_RECORDS", "Set %d value(s) for %q/%s", len(grp.items), grp.fqdn, grp.typ)
	}

	return result, lastErr
}

// ----- DeleteRecords --------------------------------------------------------

// deleteRecords removes matching values from RRsets. Records not found in the
// zone are silently ignored. When all values of an RRset are removed the
// entire RRset is deleted.
func (p *Provider) deleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, err
	}

	nz := normalizeZone(zone)
	zoneID, err := p.getZoneID(ctx, nz)
	if err != nil {
		return nil, err
	}

	// Group input by (FQDN, type). Type may be "" (wildcard).
	type key struct{ fqdn, typ string }
	type group struct {
		fqdn string
		typ  string
		recs []libdns.Record
	}
	var order []key
	groups := map[key]*group{}

	for _, r := range records {
		rr := r.RR()
		fqdn := recordFQDN(rr.Name, nz)
		typ := strings.ToUpper(rr.Type)
		k := key{fqdn, typ}
		g, ok := groups[k]
		if !ok {
			g = &group{fqdn: fqdn, typ: typ}
			groups[k] = g
			order = append(order, k)
		}
		g.recs = append(g.recs, r)
	}

	p.logInfo("DELETE_RECORDS", "Deleting %d group(s) from zone %q", len(groups), nz)

	var result []libdns.Record
	var lastErr error

	for _, k := range order {
		grp := groups[k]

		var rrsets []Record
		if grp.typ == "" {
			// Wildcard type: affect all RRsets at this name.
			all, err := p.listRRsetsAtName(ctx, zoneID, grp.fqdn)
			if err != nil {
				p.logError("DELETE_RECORDS", "Failed to list RRsets for %q: %v", grp.fqdn, err)
				lastErr = err
				continue
			}
			rrsets = all
		} else {
			existing, err := p.getRRset(ctx, zoneID, grp.fqdn, grp.typ)
			if err != nil {
				p.logError("DELETE_RECORDS", "Failed to get RRset %q/%s: %v", grp.fqdn, grp.typ, err)
				lastErr = err
				continue
			}
			if existing != nil {
				rrsets = []Record{*existing}
			}
		}

		for _, rrset := range rrsets {
			deleted, err := p.applyDelete(ctx, zoneID, nz, rrset, grp.recs)
			if err != nil {
				lastErr = err
				continue
			}
			result = append(result, deleted...)
		}
	}

	return result, lastErr
}

// applyDelete computes which values to remove from an existing RRset, issues
// the appropriate PATCH or DELETE, and returns the removed records.
func (p *Provider) applyDelete(ctx context.Context, zoneID, zone string, rrset Record, toDelete []libdns.Record) ([]libdns.Record, error) {
	var removed, remaining []RecordItem

	for _, item := range rrset.Records {
		if matchesDeleteCriteria(item, rrset, toDelete) {
			removed = append(removed, item)
		} else {
			remaining = append(remaining, item)
		}
	}

	if len(removed) == 0 {
		return nil, nil
	}

	if len(remaining) == 0 {
		if err := p.deleteRRset(ctx, zoneID, rrset.ID); err != nil {
			return nil, err
		}
	} else {
		patch := rrsetUpdatePayload{TTL: rrset.TTL, Records: remaining}
		if err := p.patchRRset(ctx, zoneID, rrset.ID, patch); err != nil {
			return nil, err
		}
	}

	nz := normalizeZone(zone)
	ttl := time.Duration(rrset.TTL) * time.Second
	fqdn := ensureTrailingDot(strings.ToLower(rrset.Name))
	rel := recordRelName(fqdn, nz)

	out := make([]libdns.Record, 0, len(removed))
	for _, item := range removed {
		data := contentToData(rrset.Type, item.Content)
		rr := libdns.RR{Name: rel, TTL: ttl, Type: rrset.Type, Data: data}
		parsed, err := rr.Parse()
		if err != nil {
			out = append(out, rr)
		} else {
			out = append(out, parsed)
		}
	}
	return out, nil
}

// matchesDeleteCriteria reports whether item in rrset should be removed given
// the provided delete criteria. An empty Type, zero TTL, or empty Data on a
// criterion acts as a wildcard for that field.
func matchesDeleteCriteria(item RecordItem, rrset Record, criteria []libdns.Record) bool {
	for _, del := range criteria {
		rr := del.RR()

		// Type: empty means wildcard.
		if rr.Type != "" && !strings.EqualFold(rr.Type, rrset.Type) {
			continue
		}

		// TTL: 0 means wildcard.
		if rr.TTL != 0 && clampTTL(int(rr.TTL.Seconds())) != rrset.TTL {
			continue
		}

		// Value: empty means wildcard.
		if rr.Data != "" {
			wantContent := dataToContent(rrset.Type, rr.Data)
			if item.Content != wantContent {
				continue
			}
		}

		return true
	}
	return false
}

// ----- ListZones ------------------------------------------------------------

func (p *Provider) listZones(ctx context.Context) ([]libdns.Zone, error) {
	p.logDebug("LIST_ZONES", "Fetching all zones")

	var all []libdns.Zone

	for offset := 0; ; {
		apiURL := fmt.Sprintf("%s/zones?limit=%d&offset=%d", p.getAPIBase(), cPageSize, offset)
		data, err := p.makeAPIRequest(ctx, httpGET, apiURL, nil)
		if err != nil {
			p.logError("LIST_ZONES", "Failed to fetch zones: %v", err)
			return nil, err
		}

		var page paginatedZones
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("unmarshal zones: %w", err)
		}

		for _, z := range page.Result {
			all = append(all, libdns.Zone{Name: ensureTrailingDot(z.Name)})
		}

		if page.NextOffset <= 0 || len(all) >= page.Count {
			break
		}
		offset = page.NextOffset
	}

	p.logInfo("LIST_ZONES", "Found %d zone(s)", len(all))
	return all, nil
}
