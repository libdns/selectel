// Package selectel implements a DNS record management client compatible
// with the libdns interfaces for Selectel DNS v2 API.
package selectel

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Selectel DNS v2 API.
//
// All public methods are safe for concurrent use. Operations on different
// zones run in parallel; operations on the same zone are serialised to
// avoid races at the API level.
//
// SetRecords is non-atomic: if an error occurs mid-batch, some records
// may have been updated while others were not.
type Provider struct {
	// User is the Selectel service-user login (required).
	User string `json:"user,omitempty"`
	// Password is the Selectel service-user password (required).
	Password string `json:"password,omitempty"`
	// AccountId is the Selectel account ID (required).
	AccountId string `json:"account_id,omitempty"`
	// ProjectName is the Selectel project name that owns the DNS zones (required).
	ProjectName string `json:"project_name,omitempty"`

	// EnableDebugLogging enables verbose DEBUG-level log output for all DNS
	// operations. INFO and ERROR messages are always emitted when a Logger is
	// set (or automatically created). When Logger is nil and EnableDebugLogging
	// is true, a logger writing to os.Stderr is created automatically.
	EnableDebugLogging bool `json:"enable_debug_logging,omitempty"`

	// HTTPRequestRetryConfiguration controls retry behaviour for transient
	// HTTP failures. A zero value enables sensible defaults; see
	// CreateDefaultHTTPRequestRetryConfiguration.
	HTTPRequestRetryConfiguration HTTPRequestRetryConfiguration

	// Logger receives diagnostic messages. When nil and EnableDebugLogging is
	// true, a *log.Logger writing to os.Stderr is created automatically. When
	// nil and EnableDebugLogging is false, the provider is completely silent.
	// Integrations (e.g. caddy-dns/selectel) may inject a structured logger here.
	Logger Logger

	// --- private token state ---
	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time

	// --- private zone ID cache ---
	cacheMu   sync.RWMutex
	zoneCache map[string]string // normalised zone FQDN → zone ID

	// --- private per-zone operation locks ---
	locksMu   sync.Mutex
	zoneLocks map[string]*sync.Mutex

	// --- private shared HTTP client ---
	clientOnce sync.Once
	httpClient *http.Client

	// --- private logger initialisation ---
	logOnce      sync.Once
	activeLogger Logger

	// --- overrides for testing (empty = use package defaults) ---
	apiBase   string
	tokenBase string
}

// getAPIBase returns the DNS API base URL, falling back to the default.
func (p *Provider) getAPIBase() string {
	if p.apiBase != "" {
		return p.apiBase
	}
	return cAPIBaseURL
}

// getTokenBase returns the Keystone token URL, falling back to the default.
func (p *Provider) getTokenBase() string {
	if p.tokenBase != "" {
		return p.tokenBase
	}
	return cTokensURL
}

// getLogger returns the active Logger, initialising it once on first call.
func (p *Provider) getLogger() Logger {
	p.logOnce.Do(func() {
		if p.Logger != nil {
			p.activeLogger = p.Logger
		} else if p.EnableDebugLogging {
			// 0 flags: we manage the timestamp ourselves in emit.
			p.activeLogger = log.New(os.Stderr, "[selectel-libdns] ", 0)
		}
	})
	return p.activeLogger
}

// logDebug emits a DEBUG entry. Suppressed when EnableDebugLogging is false.
func (p *Provider) logDebug(op, format string, args ...any) {
	if !p.EnableDebugLogging {
		return
	}
	p.emit("DEBUG", op, format, args...)
}

// logInfo emits an INFO entry.
func (p *Provider) logInfo(op, format string, args ...any) {
	p.emit("INFO", op, format, args...)
}

// logError emits an ERROR entry.
func (p *Provider) logError(op, format string, args ...any) {
	p.emit("ERROR", op, format, args...)
}

func (p *Provider) emit(level, op, format string, args ...any) {
	l := p.getLogger()
	if l == nil {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	// Prepend timestamp, level, and operation name to the caller's format string.
	l.Printf("[%s] [%s] [%s] "+format, append([]any{ts, level, op}, args...)...)
}

// sharedClient returns the shared HTTP client, initialising it on first call.
func (p *Provider) sharedClient() *http.Client {
	p.clientOnce.Do(func() {
		p.httpClient = &http.Client{
			Timeout: cHTTPClientTimeout,
			Transport: &http.Transport{
				MaxIdleConns:    100,
				IdleConnTimeout: 90 * time.Second,
			},
		}
	})
	return p.httpClient
}

// getZoneLock returns the per-zone Mutex for zone, creating it if necessary.
// zone must be a normalised FQDN (lower-case, trailing dot).
func (p *Provider) getZoneLock(zone string) *sync.Mutex {
	p.locksMu.Lock()
	defer p.locksMu.Unlock()
	if p.zoneLocks == nil {
		p.zoneLocks = make(map[string]*sync.Mutex)
	}
	if p.zoneLocks[zone] == nil {
		p.zoneLocks[zone] = &sync.Mutex{}
	}
	return p.zoneLocks[zone]
}

// currentToken returns the active token under tokenMu.
func (p *Provider) currentToken() string {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()
	return p.token
}

// ----- libdns interface methods ---------------------------------------------

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	nz := normalizeZone(zone)
	mu := p.getZoneLock(nz)
	mu.Lock()
	defer mu.Unlock()
	return p.getRecords(ctx, zone)
}

// AppendRecords adds records to the zone without modifying existing records.
// Returns only the records that were actually created.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	nz := normalizeZone(zone)
	mu := p.getZoneLock(nz)
	mu.Lock()
	defer mu.Unlock()
	return p.appendRecords(ctx, zone, records)
}

// SetRecords ensures the given records are the only members of their RRsets.
// For each (name, type) pair in the input, any existing records with that
// pair are replaced by exactly the provided values.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	nz := normalizeZone(zone)
	mu := p.getZoneLock(nz)
	mu.Lock()
	defer mu.Unlock()
	return p.setRecords(ctx, zone, records)
}

// DeleteRecords deletes records that exactly match the input from the zone.
// Records not present in the zone are silently ignored.
// Type, TTL, and Data may be left empty to act as wildcards.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	nz := normalizeZone(zone)
	mu := p.getZoneLock(nz)
	mu.Lock()
	defer mu.Unlock()
	return p.deleteRecords(ctx, zone, records)
}

// ListZones returns all DNS zones available to this provider.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, err
	}
	return p.listZones(ctx)
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
