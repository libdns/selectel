//go:build integration

package selectel_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
	selectel "github.com/libdns/selectel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupIntegration loads credentials from .env (if present) and the process
// environment, then returns a configured Provider and the target zone. Required
// SELECTEL_* variables must all be present; otherwise the test is skipped.
func setupIntegration(t *testing.T) (*selectel.Provider, string, context.Context) {
	t.Helper()

	// .env is optional – ignore absence.
	_ = godotenv.Load(".env")

	required := []string{
		"SELECTEL_USER",
		"SELECTEL_PASSWORD",
		"SELECTEL_ACCOUNT_ID",
		"SELECTEL_PROJECT_NAME",
		"SELECTEL_ZONE",
	}
	for _, key := range required {
		if os.Getenv(key) == "" {
			t.Skipf("skipping integration test: %s is not set", key)
		}
	}

	provider := &selectel.Provider{
		User:               os.Getenv("SELECTEL_USER"),
		Password:           os.Getenv("SELECTEL_PASSWORD"),
		AccountId:          os.Getenv("SELECTEL_ACCOUNT_ID"),
		ProjectName:        os.Getenv("SELECTEL_PROJECT_NAME"),
		EnableDebugLogging: true,
	}
	return provider, os.Getenv("SELECTEL_ZONE"), context.Background()
}

// integrationRecords returns a set of test records relative to the given zone.
func integrationRecords(zone string) []libdns.Record {
	return []libdns.Record{
		libdns.RR{Type: "A", Name: fmt.Sprintf("libdns-inttest-1.%s.", zone), Data: "1.2.3.1", TTL: 61 * time.Second},
		libdns.RR{Type: "A", Name: "libdns-inttest-2", Data: "1.2.3.2", TTL: 61 * time.Second},
		libdns.RR{Type: "TXT", Name: "libdns-inttest-1", Data: "txt value one", TTL: 61 * time.Second},
		libdns.RR{Type: "TXT", Name: fmt.Sprintf("libdns-inttest-2.%s.", zone), Data: "txt value two", TTL: 61 * time.Second},
	}
}

// ----- ListZones ------------------------------------------------------------

func TestProvider_ListZones(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)

	zones, err := provider.ListZones(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, zones, "expected at least one zone")

	var found bool
	for _, z := range zones {
		if z.Name == zone || z.Name == zone+"." {
			found = true
			break
		}
	}
	assert.True(t, found, "test zone %q not found in ListZones response", zone)
	t.Logf("ListZones: %d zone(s)", len(zones))
}

// ----- GetRecords -----------------------------------------------------------

func TestProvider_GetRecords(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)

	// Best-effort cleanup of leftovers from previous runs.
	_, _ = provider.DeleteRecords(ctx, zone, integrationRecords(zone))

	records, err := provider.GetRecords(ctx, zone)
	require.NoError(t, err)
	require.NotNil(t, records)
	assert.NotEmpty(t, records, "expected at least one record in zone")
	t.Logf("GetRecords: %d record(s)", len(records))
}

// ----- AppendRecords --------------------------------------------------------

func TestProvider_AppendRecords(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)
	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, zone, integrationRecords(zone))
	})

	recs := []libdns.Record{
		libdns.RR{Type: "A", Name: "libdns-inttest-append", Data: "10.0.0.1", TTL: 300 * time.Second},
		libdns.RR{Type: "TXT", Name: "libdns-inttest-append", Data: "append test", TTL: 300 * time.Second},
	}

	created, err := provider.AppendRecords(ctx, zone, recs)
	require.NoError(t, err)
	assert.Len(t, created, 2, "expected 2 records created")

	// Appending the same records again must not fail and must not duplicate.
	created2, err := provider.AppendRecords(ctx, zone, recs)
	require.NoError(t, err)
	assert.Empty(t, created2, "second append of identical records should return nothing new")

	// Cleanup
	_, _ = provider.DeleteRecords(ctx, zone, recs)
}

// ----- SetRecords -----------------------------------------------------------

func TestProvider_SetRecords(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)

	recs := []libdns.Record{
		libdns.RR{Type: "A", Name: "libdns-inttest-set", Data: "10.0.0.1", TTL: 62 * time.Second},
	}

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, zone, recs)
	})

	set, err := provider.SetRecords(ctx, zone, recs)
	require.NoError(t, err)
	assert.NotEmpty(t, set)

	// SetRecords again with different value should replace, not add.
	recs2 := []libdns.Record{
		libdns.RR{Type: "A", Name: "libdns-inttest-set", Data: "10.0.0.2", TTL: 62 * time.Second},
	}
	set2, err := provider.SetRecords(ctx, zone, recs2)
	require.NoError(t, err)
	assert.NotEmpty(t, set2)
}

// ----- DeleteRecords --------------------------------------------------------

func TestProvider_DeleteRecords(t *testing.T) {
	provider, zone, ctx := setupIntegration(t)

	recs := []libdns.Record{
		libdns.RR{Type: "TXT", Name: "libdns-inttest-del", Data: "delete me", TTL: 300 * time.Second},
	}

	_, err := provider.AppendRecords(ctx, zone, recs)
	require.NoError(t, err)

	deleted, err := provider.DeleteRecords(ctx, zone, recs)
	require.NoError(t, err)
	assert.Len(t, deleted, 1)

	// Second delete of the same records should succeed and return nothing.
	deleted2, err := provider.DeleteRecords(ctx, zone, recs)
	require.NoError(t, err)
	assert.Empty(t, deleted2)
}
