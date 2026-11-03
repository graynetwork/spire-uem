package config

import (
	"bufio"
	"os"
	"strings"
	"time"
)

// ServerConfig holds configuration for spire-server.
type ServerConfig struct {
	ListenAddr     string
	DatabaseURL    string
	MigrationsPath string
	AdminUsername  string
	AdminPassword  string
}

// AgentConfig holds configuration for the spired client daemon.
type AgentConfig struct {
	ServerURL       string
	TokenPath       string
	CheckinInterval time.Duration
	PollInterval    time.Duration
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
			ListenAddr:     ":8080",
			DatabaseURL:    "postgres://spire:spirepassword@localhost:5432/spire_uem?sslmode=disable",
			MigrationsPath: "migrations/000001_init_schema.up.sql",
			AdminUsername:  "admin",
			AdminPassword:  "changeme",
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
