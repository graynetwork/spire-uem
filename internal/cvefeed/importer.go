// Package cvefeed imports the Debian Security Tracker JSON feed into the database and
// schedules periodic refreshes. It streams the (large) feed through cvematch.StreamDebianFeed
// into a staging table, so the raw body is never held in memory twice and the live data is
// swapped atomically.
package cvefeed

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/cvematch"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	// DefaultFeedURL is the canonical Debian Security Tracker JSON endpoint.
	DefaultFeedURL = "https://security-tracker.debian.org/tracker/data/json"
	// DefaultInterval between automatic imports.
	DefaultInterval = 24 * time.Hour
	// maxFeedBytes caps the feed we will read (the real feed is ~60-90MB; this is a hard
	// safety ceiling so a misconfigured/hostile URL cannot exhaust disk or memory).
	maxFeedBytes = 512 * 1024 * 1024
	// fetchTimeout bounds a single HTTP import.
	fetchTimeout = 10 * time.Minute
)

// Config resolves the importer settings from env first, then DB settings, then defaults.
type Config struct {
	// Enabled turns on the automatic periodic import. It is off by default: the server
	// downloads nothing until an admin enables it (cve.feed_enabled) or sets
	// SPIRE_CVE_FEED_ENABLED=true. Manual imports and offline uploads work either way.
	Enabled bool
	// EnabledFromEnv reports that SPIRE_CVE_FEED_ENABLED decided Enabled, so the stored
	// setting has no effect.
	EnabledFromEnv bool
	URL            string
	FilePath       string // SPIRE_CVE_FEED_FILE: offline import source (takes priority over URL)
	Interval       time.Duration
}

// Importer runs feed imports against a Repository.
type Importer struct {
	repo *db.Repository
}

// New creates an Importer.
func New(repo *db.Repository) *Importer { return &Importer{repo: repo} }

// LoadConfig resolves importer configuration. Env wins over stored settings so an operator
// can pin behaviour without the DB. Missing/blank values fall back to defaults.
func LoadConfig(ctx context.Context, repo *db.Repository) Config {
	cfg := Config{Enabled: false, URL: DefaultFeedURL, Interval: DefaultInterval}

	// DB settings (category "cve"). Only an explicit true enables the automatic import.
	if s, err := repo.GetSetting(ctx, "cve.feed_enabled"); err == nil && s != nil {
		cfg.Enabled = strings.TrimSpace(string(s.Value)) == "true"
	}
	if s, err := repo.GetSetting(ctx, "cve.feed_url"); err == nil && s != nil {
		if u := strings.Trim(strings.TrimSpace(string(s.Value)), `"`); u != "" {
			cfg.URL = u
		}
	}
	if s, err := repo.GetSetting(ctx, "cve.feed_interval_hours"); err == nil && s != nil {
		if h, err := strconv.Atoi(strings.TrimSpace(string(s.Value))); err == nil && h > 0 {
			cfg.Interval = time.Duration(h) * time.Hour
		}
	}

	// Env overrides.
	if v := strings.TrimSpace(os.Getenv("SPIRE_CVE_FEED_URL")); v != "" {
		cfg.URL = v
	}
	if v := strings.TrimSpace(os.Getenv("SPIRE_CVE_FEED_FILE")); v != "" {
		cfg.FilePath = v
	}
	if v := strings.TrimSpace(os.Getenv("SPIRE_CVE_FEED_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Interval = d
		} else if h, err := strconv.Atoi(v); err == nil && h > 0 {
			cfg.Interval = time.Duration(h) * time.Hour
		}
	}
	if v := strings.TrimSpace(os.Getenv("SPIRE_CVE_FEED_ENABLED")); v != "" {
		cfg.Enabled = strings.EqualFold(v, "true") || v == "1"
		cfg.EnabledFromEnv = true
	}
	return cfg
}

// ImportFromReader streams the feed from r into the database. source is a human label for
// provenance. It is the shared core of the URL, file and admin-upload paths.
func (im *Importer) ImportFromReader(ctx context.Context, r io.Reader, source string) (records, cves int, err error) {
	start := time.Now()
	limited := io.LimitReader(r, maxFeedBytes+1)

	importer, err := im.repo.BeginCVEImport(ctx)
	if err != nil {
		return 0, 0, err
	}
	var read int64
	counting := &countingReader{r: limited, n: &read}

	n, perr := cvematch.StreamDebianFeed(counting, func(e types.CVEEntry) error {
		return importer.Add(e)
	})
	if perr != nil {
		importer.Rollback()
		_ = im.repo.RecordCVEFeedError(ctx, source, perr.Error())
		return 0, 0, perr
	}
	if read > maxFeedBytes {
		importer.Rollback()
		msg := fmt.Sprintf("feed exceeded size cap of %d bytes", maxFeedBytes)
		_ = im.repo.RecordCVEFeedError(ctx, source, msg)
		return 0, 0, fmt.Errorf("%s", msg)
	}
	_ = n
	records, cves, err = importer.Commit(source, time.Since(start))
	if err != nil {
		_ = im.repo.RecordCVEFeedError(ctx, source, err.Error())
		return 0, 0, err
	}
	return records, cves, nil
}

// ImportFromFile imports an offline feed file (air-gapped path).
func (im *Importer) ImportFromFile(ctx context.Context, path string) (int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		_ = im.repo.RecordCVEFeedError(ctx, "file:"+path, err.Error())
		return 0, 0, err
	}
	defer f.Close()
	return im.ImportFromReader(ctx, f, "file:"+path)
}

// ImportFromURL fetches and imports the feed over HTTP with a timeout and size cap, using a
// streaming body (no second copy).
func (im *Importer) ImportFromURL(ctx context.Context, url string) (int, int, error) {
	if err := checkFeedURL(url); err != nil {
		_ = im.repo.RecordCVEFeedError(ctx, "url:"+url, err.Error())
		return 0, 0, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		_ = im.repo.RecordCVEFeedError(ctx, "url:"+url, err.Error())
		return 0, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SpireUEM-CVE-Importer")

	resp, err := feedClient.Do(req)
	if err != nil {
		_ = im.repo.RecordCVEFeedError(ctx, "url:"+url, err.Error())
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("feed HTTP %d", resp.StatusCode)
		_ = im.repo.RecordCVEFeedError(ctx, "url:"+url, msg)
		return 0, 0, fmt.Errorf("%s", msg)
	}
	return im.ImportFromReader(reqCtx, resp.Body, "url:"+url)
}

// RunOnce performs one import according to cfg (file path wins over URL), then recomputes
// fleet-wide matches. Returns the import counts.
func (im *Importer) RunOnce(ctx context.Context, cfg Config) (int, int, error) {
	var records, cves int
	var err error
	if cfg.FilePath != "" {
		records, cves, err = im.ImportFromFile(ctx, cfg.FilePath)
	} else {
		records, cves, err = im.ImportFromURL(ctx, cfg.URL)
	}
	if err != nil {
		return 0, 0, err
	}
	if devs, rerr := im.repo.RecomputeAllDeviceCVEs(ctx); rerr != nil {
		log.Printf("[cvefeed] import ok (%d records, %d CVEs) but fleet rematch failed: %v", records, cves, rerr)
	} else {
		log.Printf("[cvefeed] imported %d records / %d CVEs, rematched %d devices", records, cves, devs)
	}
	return records, cves, nil
}

// disabledRecheck is how often a disabled scheduler re-reads its config, so turning the
// automatic import on in the admin UI takes effect without a restart.
var disabledRecheck = time.Minute

// Schedule runs the automatic import while it is enabled: once shortly after startup (or
// after it is switched on) and then every cfg.Interval, until ctx is cancelled. While it is
// disabled (the default) it downloads nothing and only re-reads the setting. Intended to
// be launched in a goroutine from main.
func (im *Importer) Schedule(ctx context.Context) {
	cfg := LoadConfig(ctx, im.repo)
	if !cfg.Enabled {
		log.Printf("[cvefeed] automatic import is off (enable it on the Vulnerabilities page or with SPIRE_CVE_FEED_ENABLED=true)")
	}
	wasEnabled := cfg.Enabled
	// Initial import shortly after startup, not blocking server readiness.
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		// Re-read config each cycle so settings changes take effect without a restart.
		cfg = LoadConfig(ctx, im.repo)
		if !cfg.Enabled {
			if wasEnabled {
				log.Printf("[cvefeed] automatic import switched off")
			}
			wasEnabled = false
			timer.Reset(disabledRecheck)
			continue
		}
		if !wasEnabled {
			log.Printf("[cvefeed] automatic import switched on")
		}
		wasEnabled = true
		if _, _, err := im.RunOnce(ctx, cfg); err != nil {
			log.Printf("[cvefeed] scheduled import failed: %v", err)
		}
		interval := cfg.Interval
		if interval <= 0 {
			interval = DefaultInterval
		}
		timer.Reset(interval)
	}
}

type countingReader struct {
	r io.Reader
	n *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += int64(n)
	return n, err
}

// feedClient fetches the feed over TLS 1.2+ and refuses redirects to a non-https URL.
var feedClient = &http.Client{
	Transport: &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return checkFeedURL(req.URL.String())
	},
}

// checkFeedURL requires an https feed URL. SPIRE_CVE_FEED_ALLOW_HTTP=1 allows plain http, for a
// local mirror on a trusted network.
func checkFeedURL(raw string) error {
	u, err := neturl.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid CVE feed URL %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if os.Getenv("SPIRE_CVE_FEED_ALLOW_HTTP") == "1" {
			return nil
		}
		return fmt.Errorf("CVE feed URL must use https (set SPIRE_CVE_FEED_ALLOW_HTTP=1 for a trusted local mirror)")
	default:
		return fmt.Errorf("CVE feed URL must use https, got scheme %q", u.Scheme)
	}
}
