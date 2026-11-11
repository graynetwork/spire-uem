package types

import "time"

// RecentHostActivity represents a recently active managed endpoint.
type RecentHostActivity struct {
	DeviceID   string    `json:"device_id"`
	Hostname   string    `json:"hostname"`
	LastSeenAt time.Time `json:"last_seen_at"`
	LastSeen   string    `json:"last_seen"`
}

// RecentUserActivity represents a recent administrative user login or activity event.
type RecentUserActivity struct {
	Username    string    `json:"username"`
	LastLoginAt time.Time `json:"last_login_at"`
	LastLogin   string    `json:"last_login"`
}

// UpdateStatusBreakdown holds donut chart slices for update readiness.
type UpdateStatusBreakdown struct {
	UpToDate     int `json:"up_to_date"`
	NeedsUpdates int `json:"needs_updates"`
	Errored      int `json:"errored"`
}

// DashboardMetrics holds the aggregated 6-metric summary ribbon and telemetry cards.
type DashboardMetrics struct {
	// 6-Metric Stat Ribbon
	TotalHosts       int `json:"total_hosts"`
	UpToDateHosts    int `json:"up_to_date_hosts"`
	NeedsUpdates     int `json:"needs_updates"`
	NeedsReboot      int `json:"needs_reboot"`
	OutdatedPackages int `json:"outdated_packages"`
	SecurityUpdates  int `json:"security_updates"`

	// Status breakdowns
	ApprovedHosts int `json:"approved_hosts"`
	PendingHosts  int `json:"pending_hosts"`
	RevokedHosts  int `json:"revoked_hosts"`

	// Attestation breakdowns
	AttestedHosts   int `json:"attested_hosts"`
	UnattestedHosts int `json:"unattested_hosts"`
	FailedHosts     int `json:"failed_hosts"`

	// 2x2 Compliance Matrix
	CompliantHosts  int `json:"compliant_hosts"`
	WarningHosts    int `json:"warning_hosts"`
	CriticalHosts   int `json:"critical_hosts"`

	// Activity Feeds
	RecentHosts []RecentHostActivity `json:"recent_hosts"`
	RecentUsers []RecentUserActivity `json:"recent_users"`

	// Visualizations Data
	OSDistribution map[string]int        `json:"os_distribution"`
	UpdateStatus   UpdateStatusBreakdown `json:"update_status"`

	// Benchmark Telemetry
	BenchmarkSummary *BenchmarkSummary `json:"benchmark_summary,omitempty"`
	ActiveScans      []*BenchmarkScan  `json:"active_scans,omitempty"`
}
