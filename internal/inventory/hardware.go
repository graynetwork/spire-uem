package inventory

import (
	"fmt"
	"os"
	"strings"
)

// GetHardwareUUID reads /sys/class/dmi/id/product_uuid and falls back to /etc/machine-id.
// In containerized test environments (/.dockerenv present), /etc/machine-id is checked first
// so each container can supply a distinct mock machine-id.
func GetHardwareUUID() (string, error) {
	if envUUID := strings.TrimSpace(os.Getenv("SPIRE_HARDWARE_UUID")); envUUID != "" {
		return envUUID, nil
	}

	paths := []string{
		"/sys/class/dmi/id/product_uuid",
		"/etc/machine-id",
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		paths = []string{
			"/etc/machine-id",
			"/sys/class/dmi/id/product_uuid",
		}
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		uuid := strings.TrimSpace(string(data))
		if uuid != "" {
			return uuid, nil
		}
	}

	return "", fmt.Errorf("unable to read hardware UUID from /sys/class/dmi/id/product_uuid or /etc/machine-id")
}

// GetHostname returns the machine's OS hostname.
func GetHostname() string {
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		return "unknown-debian-host"
	}
	return strings.TrimSpace(h)
}
