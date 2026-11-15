package config

import (
	"bufio"
	"os"
	"strings"
	"time"
)

// ServerConfig holds configuration for spire-server.
type ServerConfig struct {
	ListenAddr       string
	DatabaseURL      string
	MigrationsPath   string
	AdminUsername    string
	AdminPassword    string
	SIEMSyslogAddr   string
	KEKPath          string
	WipeSigningKeyPath string
	AptRepoDir       string
	BundleStorageDir string
	EnforceHTTPS     bool
	// MultiInstance signals this server runs as one of several instances behind a load
	// balancer sharing one database. It turns on gateway cross-instance routing and makes
	// a shared SPIRE_SESSION_SECRET mandatory.
	MultiInstance bool
	// InstanceID uniquely identifies this process in a multi-instance deployment. Defaults
	// to "<hostname>:<listen_addr>" when unset.
	InstanceID string
	// TLSCertFile / TLSKeyFile make spire-server terminate TLS itself (SPIRE_TLS_CERT_FILE /
	// SPIRE_TLS_KEY_FILE). See ResolveServerTransport for when plain HTTP is allowed.
	TLSCertFile string
	TLSKeyFile  string
	// AllowInsecureHTTP permits plain HTTP on a reachable address (SPIRE_ALLOW_INSECURE_HTTP=1).
	// Lab and test networks only.
	AllowInsecureHTTP bool
}

// AgentConfig holds configuration for the spired client daemon.
type AgentConfig struct {
	ServerURL       string
	TokenPath       string
	CheckinInterval time.Duration
	PollInterval    time.Duration
	// AllowInsecureHTTP lets the agent talk to a non-loopback server over plain HTTP
	// (allow_insecure_http / SPIRE_AGENT_ALLOW_INSECURE_HTTP=1). Lab networks only.
	AllowInsecureHTTP bool
}

// Config aggregates server and agent configurations.
type Config struct {
	Server ServerConfig
	Agent  AgentConfig
}

// Load loads configuration from an optional YAML file and environment variable overrides.
func Load(configPath string) *Config {
	cfg := &Config{
		Server: ServerConfig{
			ListenAddr:       ":8080",
			DatabaseURL:      "postgres://spire:spirepassword@localhost:5432/spire_uem?sslmode=disable",
			MigrationsPath:   "migrations/000001_init_schema.up.sql",
			AdminUsername:    "admin",
			AdminPassword:    "", // static break-glass account disabled unless explicitly configured
			KEKPath:          "internal/crypto/kek.pem",
			WipeSigningKeyPath: "internal/crypto/wipe-signing.pem",
			AptRepoDir:       "/var/www/apt/spire",
			BundleStorageDir: "/var/lib/spire/storage/bundles",
			EnforceHTTPS:     false,
		},
		Agent: AgentConfig{
			ServerURL:       "http://localhost:8080",
			TokenPath:       "/etc/spire/token",
			CheckinInterval: 5 * time.Minute,
			PollInterval:    5 * time.Second,
		},
	}

	if configPath != "" {
		parseSimpleYAML(configPath, cfg)
	}

	if v := os.Getenv("SPIRE_LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	} else if v := os.Getenv("PORT"); v != "" {
		if strings.HasPrefix(v, ":") {
			cfg.Server.ListenAddr = v
		} else {
			cfg.Server.ListenAddr = ":" + v
		}
	}

	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.Server.DatabaseURL = v
	}
	if v := os.Getenv("SPIRE_MIGRATIONS_PATH"); v != "" {
		cfg.Server.MigrationsPath = v
	}
	if v := os.Getenv("SPIRE_ADMIN_USER"); v != "" {
		cfg.Server.AdminUsername = v
	}
	if v := os.Getenv("SPIRE_ADMIN_PASSWORD"); v != "" {
		cfg.Server.AdminPassword = v
	}
	if v := os.Getenv("SPIRE_SIEM_SYSLOG_ADDR"); v != "" {
		cfg.Server.SIEMSyslogAddr = strings.TrimSpace(v)
	}
	if v := os.Getenv("SPIRE_KEK_PATH"); v != "" {
		cfg.Server.KEKPath = strings.TrimSpace(v)
	}
	if v := os.Getenv("SPIRE_WIPE_SIGNING_KEY_PATH"); v != "" {
		cfg.Server.WipeSigningKeyPath = strings.TrimSpace(v)
	}
	if v := os.Getenv("SPIRE_APT_REPO_DIR"); v != "" {
		cfg.Server.AptRepoDir = strings.TrimSpace(v)
	}
	if v := os.Getenv("SPIRE_BUNDLE_STORAGE_DIR"); v != "" {
		cfg.Server.BundleStorageDir = strings.TrimSpace(v)
	}
	if v := os.Getenv("SPIRE_ENFORCE_HTTPS"); v != "" {
		cfg.Server.EnforceHTTPS = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("SPIRE_MULTI_INSTANCE"); v != "" {
		cfg.Server.MultiInstance = strings.EqualFold(v, "true") || v == "1"
	}
	if v := strings.TrimSpace(os.Getenv("SPIRE_INSTANCE_ID")); v != "" {
		cfg.Server.InstanceID = v
		cfg.Server.MultiInstance = true // an explicit instance id implies multi-instance
	}
	if v := strings.TrimSpace(os.Getenv("SPIRE_TLS_CERT_FILE")); v != "" {
		cfg.Server.TLSCertFile = v
	}
	if v := strings.TrimSpace(os.Getenv("SPIRE_TLS_KEY_FILE")); v != "" {
		cfg.Server.TLSKeyFile = v
	}
	if v := strings.TrimSpace(os.Getenv("SPIRE_ALLOW_INSECURE_HTTP")); v != "" {
		cfg.Server.AllowInsecureHTTP = strings.EqualFold(v, "true") || v == "1"
	}
	if v := strings.TrimSpace(os.Getenv("SPIRE_AGENT_ALLOW_INSECURE_HTTP")); v != "" {
		cfg.Agent.AllowInsecureHTTP = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("SPIRE_SERVER_URL"); v != "" {
		cfg.Agent.ServerURL = strings.TrimRight(v, "/")
	}
	if v := os.Getenv("SPIRE_TOKEN_PATH"); v != "" {
		cfg.Agent.TokenPath = v
	}
	if v := os.Getenv("SPIRE_CHECKIN_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Agent.CheckinInterval = d
		}
	}
	if v := os.Getenv("SPIRE_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Agent.PollInterval = d
		}
	}

	return cfg
}

// parseSimpleYAML parses the flat two-level YAML used in packaging/config.example.yaml.
func parseSimpleYAML(path string, cfg *Config) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)

		switch section {
		case "server":
			switch key {
			case "listen_addr":
				if val != "" {
					cfg.Server.ListenAddr = val
				}
			case "database_url":
				if val != "" {
					cfg.Server.DatabaseURL = val
				}
			case "migrations_path":
				if val != "" {
					cfg.Server.MigrationsPath = val
				}
			case "admin_user":
				if val != "" {
					cfg.Server.AdminUsername = val
				}
			case "admin_password":
				if val != "" {
					cfg.Server.AdminPassword = val
				}
			case "kek_path":
				if val != "" {
					cfg.Server.KEKPath = val
				}
			case "bundle_storage_dir":
				if val != "" {
					cfg.Server.BundleStorageDir = val
				}
			case "enforce_https":
				cfg.Server.EnforceHTTPS = strings.EqualFold(val, "true") || val == "1"
			case "tls_cert_file":
				cfg.Server.TLSCertFile = val
			case "tls_key_file":
				cfg.Server.TLSKeyFile = val
			case "allow_insecure_http":
				cfg.Server.AllowInsecureHTTP = strings.EqualFold(val, "true") || val == "1"
			}
		case "agent":
			switch key {
			case "server_url":
				if val != "" {
					cfg.Agent.ServerURL = strings.TrimRight(val, "/")
				}
			case "token_path":
				if val != "" {
					cfg.Agent.TokenPath = val
				}
			case "allow_insecure_http":
				cfg.Agent.AllowInsecureHTTP = strings.EqualFold(val, "true") || val == "1"
			case "checkin_interval":
				if d, err := time.ParseDuration(val); err == nil {
					cfg.Agent.CheckinInterval = d
				}
			case "poll_interval":
				if d, err := time.ParseDuration(val); err == nil {
					cfg.Agent.PollInterval = d
				}
			}
		}
	}
}
