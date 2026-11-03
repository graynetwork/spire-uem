package inventory

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
)

// GetActiveSession runs loginctl list-sessions --no-legend to identify the active seat0 user.
func GetActiveSession() (string, error) {
	cmd := exec.Command("loginctl", "list-sessions", "--no-legend")
	out, err := cmd.Output()
	if err != nil {
		return "", nil
	}

	var fallbackUser string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Standard loginctl list-sessions columns: SESSION UID USER SEAT TTY ...
		if len(fields) >= 4 {
			user := fields[2]
			seat := fields[3]
			if seat == "seat0" {
				return user, nil
			}
			if fallbackUser == "" {
				fallbackUser = user
			}
		} else if len(fields) >= 3 && fallbackUser == "" {
			fallbackUser = fields[2]
		}
	}
	return fallbackUser, nil
}
