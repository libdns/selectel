package selectel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// authToken is the fake Keystone token used across httptest helpers.
const authToken = "fake-iam-token-abc123"

// testProvider creates a Provider pre-configured with a fake token and pointed
// at the given API server, with retries disabled for speed.
func testProvider(apiSrv *httptest.Server) *Provider {
	p := &Provider{
		User:        "u",
		Password:    "p",
		AccountId:   "a",
		ProjectName: "proj",
		HTTPRequestRetryConfiguration: HTTPRequestRetryConfiguration{
			MaximumRetryAttempts:         0,
			InitialRetryDelay:            time.Millisecond,
			MaximumRetryDelay:            time.Millisecond,
			ExponentialBackoffMultiplier: 1,
		},
	}
	p.token = authToken
	p.tokenExpiry = time.Now().Add(24 * time.Hour)
	p.apiBase = apiSrv.URL
	return p
}

// testCtx returns a background context for use in httptest calls.
func testCtx() context.Context { return context.Background() }

// ----- authenticate (JSON body) ---------------------------------------------

func TestAuthenticate_JSONBodyIsValid(t *testing.T) {
	t.Parallel()

	// Verify that the auth body built from encoding/json is valid and the
	// password survives a round-trip (no injection possible).
	cases := []struct {
		name     string
		password string
	}{
		{"plain", "password123"},
		{"with quotes", `pass"word`},
		{"with backslash", `pass\word`},
		{"with both", `"p\\a\ss"`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := &Provider{
				User:        "user",
				Password:    tc.password,
				AccountId:   "account",
				ProjectName: "project",
			}

			req := keystoneAuthRequest{
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

			body, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			var round keystoneAuthRequest
			if err := json.Unmarshal(body, &round); err != nil {
				t.Fatalf("body is not valid JSON: %v", err)
			}

			got := round.Auth.Identity.Password.User.Password
			if got != tc.password {
				t.Fatalf("password round-trip: got %q, want %q", got, tc.password)
			}
		})
	}
}

// ----- getZoneID ------------------------------------------------------------

func TestGetZoneID_ExactMatch(t *testing.T) {
	t.Parallel()

	const (
		zoneID   = "zone-uuid-1"
		zoneName = "example.com."
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(paginatedZones{
			Count: 2,
			Result: []Zone{
				{ID: "other", Name: "notexample.com."},
				{ID: zoneID, Name: zoneName},
			},
		})
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	id, err := p.getZoneID(testCtx(), zoneName)
	if err != nil {
		t.Fatalf("getZoneID: %v", err)
	}
	if id != zoneID {
		t.Fatalf("zone ID = %q, want %q", id, zoneID)
	}
}

func TestGetZoneID_NotFound(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(paginatedZones{Count: 0, Result: nil})
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	_, err := p.getZoneID(testCtx(), "missing.example.com.")
	if err == nil {
		t.Fatal("expected error for missing zone, got nil")
	}
}

func TestGetZoneID_CachedOnSecondCall(t *testing.T) {
	t.Parallel()

	const zoneID = "cached-id"
	apiCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		_ = json.NewEncoder(w).Encode(paginatedZones{
			Count:  1,
			Result: []Zone{{ID: zoneID, Name: "example.com."}},
		})
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	for i := 0; i < 3; i++ {
		id, err := p.getZoneID(testCtx(), "example.com.")
		if err != nil || id != zoneID {
			t.Fatalf("call %d: id=%q err=%v", i+1, id, err)
		}
	}

	if apiCalls != 1 {
		t.Fatalf("expected 1 API call (caching), got %d", apiCalls)
	}
}

// ----- GetRecords (pagination) ----------------------------------------------

func TestGetRecords_PaginatesAllRRsets(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	rrsetCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/rrset") {
			// Zone lookup.
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
			return
		}

		rrsetCalls++
		offset := r.URL.Query().Get("offset")
		if offset == "" || offset == "0" {
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count:      2,
				NextOffset: 1,
				Result: []Record{{
					ID: "r1", Type: "A", Name: "host.example.com.", TTL: 300,
					Records: []RecordItem{{Content: "1.2.3.4"}},
				}},
			})
		} else {
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count:      2,
				NextOffset: 0,
				Result: []Record{{
					ID: "r2", Type: "TXT", Name: "host.example.com.", TTL: 300,
					Records: []RecordItem{{Content: `"hello"`}},
				}},
			})
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	records, err := p.getRecords(testCtx(), "example.com.")
	if err != nil {
		t.Fatalf("getRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records (1 A + 1 TXT), got %d", len(records))
	}
	if rrsetCalls < 2 {
		t.Fatalf("expected at least 2 /rrset calls for pagination, got %d", rrsetCalls)
	}
}

// ----- AppendRecords --------------------------------------------------------

func TestAppendRecords_CreatesWhenAbsent(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	var postedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !strings.Contains(r.URL.Path, "/rrset"):
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(paginatedRRsets{Count: 0, Result: nil})
		case r.Method == http.MethodPost:
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r.Body)
			postedBody = buf.Bytes()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	added, err := p.appendRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "A", Name: "host", Data: "1.2.3.4", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("appendRecords: %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("expected 1 record added, got %d", len(added))
	}

	var payload rrsetCreatePayload
	if err := json.Unmarshal(postedBody, &payload); err != nil {
		t.Fatalf("POST body is not valid rrsetCreatePayload: %v", err)
	}
	if payload.Type != "A" {
		t.Fatalf("POST type = %q, want A", payload.Type)
	}
	if len(payload.Records) != 1 || payload.Records[0].Content != "1.2.3.4" {
		t.Fatalf("POST records = %+v, want [{Content:1.2.3.4}]", payload.Records)
	}
}

func TestAppendRecords_MergesExisting(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	var patchBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !strings.Contains(r.URL.Path, "/rrset"):
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count: 1,
				Result: []Record{{
					ID: "r1", Type: "TXT", Name: "host.example.com.", TTL: 300,
					Records: []RecordItem{{Content: `"existing"`}},
				}},
			})
		case r.Method == http.MethodPatch:
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r.Body)
			patchBody = buf.Bytes()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	added, err := p.appendRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "TXT", Name: "host", Data: "new value", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("appendRecords: %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(added))
	}

	var patch rrsetUpdatePayload
	if err := json.Unmarshal(patchBody, &patch); err != nil {
		t.Fatalf("PATCH body invalid: %v", err)
	}
	if len(patch.Records) != 2 {
		t.Fatalf("merged records = %d, want 2 (existing + new)", len(patch.Records))
	}
}

func TestAppendRecords_SkipsDuplicates(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	patched := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !strings.Contains(r.URL.Path, "/rrset"):
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count: 1,
				Result: []Record{{
					ID: "r1", Type: "TXT", Name: "host.example.com.", TTL: 300,
					Records: []RecordItem{{Content: `"same value"`}},
				}},
			})
		case r.Method == http.MethodPatch:
			patched = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	added, err := p.appendRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "TXT", Name: "host", Data: "same value", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("appendRecords: %v", err)
	}
	if len(added) != 0 {
		t.Fatalf("expected 0 added (duplicate), got %d", len(added))
	}
	if patched {
		t.Fatal("no PATCH expected when all values already exist")
	}
}

// ----- SetRecords -----------------------------------------------------------

func TestSetRecords_ReplacesExisting(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	var patchBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !strings.Contains(r.URL.Path, "/rrset"):
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count: 1,
				Result: []Record{{
					ID: "r1", Type: "A", Name: "host.example.com.", TTL: 300,
					Records: []RecordItem{{Content: "1.2.3.4"}},
				}},
			})
		case r.Method == http.MethodPatch:
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r.Body)
			patchBody = buf.Bytes()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	set, err := p.setRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "A", Name: "host", Data: "10.0.0.1", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("setRecords: %v", err)
	}
	if len(set) != 1 {
		t.Fatalf("expected 1 record set, got %d", len(set))
	}

	// PATCH body must contain only the new value (not merged).
	var patch rrsetUpdatePayload
	if err := json.Unmarshal(patchBody, &patch); err != nil {
		t.Fatalf("PATCH body invalid: %v", err)
	}
	if len(patch.Records) != 1 || patch.Records[0].Content != "10.0.0.1" {
		t.Fatalf("PATCH records = %+v, want [{Content:10.0.0.1}]", patch.Records)
	}
}

// ----- PATCH payload contract -----------------------------------------------

func TestPatchPayload_NoNameOrType(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	var patchBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !strings.Contains(r.URL.Path, "/rrset"):
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count: 1,
				Result: []Record{{
					ID: "r1", Type: "A", Name: "host.example.com.", TTL: 300,
					Records: []RecordItem{{Content: "1.2.3.4"}},
				}},
			})
		case r.Method == http.MethodPatch:
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r.Body)
			patchBody = buf.Bytes()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)
	_, _ = p.setRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "A", Name: "host", Data: "10.0.0.1", TTL: 300 * time.Second},
	})

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(patchBody, &raw); err != nil {
		t.Fatalf("PATCH body invalid JSON: %v", err)
	}
	if _, ok := raw["name"]; ok {
		t.Fatal("PATCH body must NOT contain 'name'")
	}
	if _, ok := raw["type"]; ok {
		t.Fatal("PATCH body must NOT contain 'type'")
	}
	if _, ok := raw["id"]; ok {
		t.Fatal("PATCH body must NOT contain 'id'")
	}
	if _, ok := raw["ttl"]; !ok {
		t.Fatal("PATCH body must contain 'ttl'")
	}
	if _, ok := raw["records"]; !ok {
		t.Fatal("PATCH body must contain 'records'")
	}
}

// ----- DeleteRecords --------------------------------------------------------

func TestDeleteRecords_RemovesSpecificValue(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	var patchBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !strings.Contains(r.URL.Path, "/rrset"):
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count: 1,
				Result: []Record{{
					ID: "r1", Type: "TXT", Name: "host.example.com.", TTL: 300,
					Records: []RecordItem{
						{Content: `"keep me"`},
						{Content: `"delete me"`},
					},
				}},
			})
		case r.Method == http.MethodPatch:
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r.Body)
			patchBody = buf.Bytes()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	deleted, err := p.deleteRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "TXT", Name: "host", Data: "delete me", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("deleteRecords: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected 1 deleted, got %d", len(deleted))
	}

	var patch rrsetUpdatePayload
	if err := json.Unmarshal(patchBody, &patch); err != nil {
		t.Fatalf("PATCH body invalid: %v", err)
	}
	if len(patch.Records) != 1 || patch.Records[0].Content != `"keep me"` {
		t.Fatalf("remaining records = %+v, want [{Content:\"keep me\"}]", patch.Records)
	}
}

func TestDeleteRecords_DeletesRRsetWhenEmpty(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	deleteCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !strings.Contains(r.URL.Path, "/rrset"):
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count: 1,
				Result: []Record{{
					ID: "r1", Type: "TXT", Name: "host.example.com.", TTL: 300,
					Records: []RecordItem{{Content: `"only value"`}},
				}},
			})
		case r.Method == http.MethodDelete:
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	out, err := p.deleteRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "TXT", Name: "host", Data: "only value", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("deleteRecords: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 deleted, got %d", len(out))
	}
	if !deleteCalled {
		t.Fatal("expected DELETE /rrset/{id} when last value removed")
	}
}

func TestDeleteRecords_IgnoresNonExistent(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/rrset") {
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(paginatedRRsets{Count: 0, Result: nil})
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	out, err := p.deleteRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "TXT", Name: "ghost", Data: "value", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("expected no error for non-existent record: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 deleted, got %d", len(out))
	}
}

func TestDeleteRecords_WildcardTTL(t *testing.T) {
	t.Parallel()

	const zoneID = "z1"
	deleteCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !strings.Contains(r.URL.Path, "/rrset"):
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:  1,
				Result: []Zone{{ID: zoneID, Name: "example.com."}},
			})
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(paginatedRRsets{
				Count: 1,
				Result: []Record{{
					ID: "r1", Type: "A", Name: "host.example.com.", TTL: 3600,
					Records: []RecordItem{{Content: "1.2.3.4"}},
				}},
			})
		case r.Method == http.MethodDelete:
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	// TTL = 0 means "match any TTL".
	out, err := p.deleteRecords(testCtx(), "example.com.", []libdns.Record{
		libdns.RR{Type: "A", Name: "host", Data: "1.2.3.4", TTL: 0},
	})
	if err != nil {
		t.Fatalf("deleteRecords: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 deleted (wildcard TTL), got %d", len(out))
	}
	if !deleteCalled {
		t.Fatal("expected DELETE for wildcard-TTL match")
	}
}

// ----- ListZones ------------------------------------------------------------

func TestListZones_Paginated(t *testing.T) {
	t.Parallel()

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		offset := r.URL.Query().Get("offset")
		if offset == "" || offset == "0" {
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:      2,
				NextOffset: 1,
				Result:     []Zone{{ID: "z1", Name: "alpha.com."}},
			})
		} else {
			_ = json.NewEncoder(w).Encode(paginatedZones{
				Count:      2,
				NextOffset: 0,
				Result:     []Zone{{ID: "z2", Name: "beta.com."}},
			})
		}
	}))
	t.Cleanup(srv.Close)

	p := testProvider(srv)

	zones, err := p.listZones(testCtx())
	if err != nil {
		t.Fatalf("listZones: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
	if calls < 2 {
		t.Fatalf("expected at least 2 API calls for pagination, got %d", calls)
	}
}
