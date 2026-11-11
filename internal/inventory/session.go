package inventory

import (
	"bufio"
	"bytes"
	"os/exec"
	"os/user"
	"strings"
)

// GetActiveSession runs loginctl list-sessions --no-legend to identify the active seat0 user.
func GetActiveSession() (string, error) {
	username, _, err := GetActiveSessionDetails()
	return username, err
}

// GetActiveSessionDetails returns the active seat0 username and numeric UID for D-Bus session bus targeting.
func GetActiveSessionDetails() (string, string, error) {
	cmd := exec.Command("loginctl", "list-sessions", "--no-legend")
	out, err := cmd.Output()
	if err != nil {
		return "", "", nil
	}

	var fallbackUser, fallbackUID string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Standard loginctl list-sessions columns: SESSION UID USER SEAT TTY ...
		if len(fields) >= 4 {
			uid := fields[1]
			uname := fields[2]
			seat := fields[3]
			if seat == "seat0" {
				return uname, uid, nil
			}
			if fallbackUser == "" {
				fallbackUser = uname
				fallbackUID = uid
			}
		} else if len(fields) >= 3 && fallbackUser == "" {
			fallbackUID = fields[1]
			fallbackUser = fields[2]
		}
	}

	if fallbackUser != "" && fallbackUID == "" {
		if u, err := user.Lookup(fallbackUser); err == nil {
			fallbackUID = u.Uid
		}
	}
	return fallbackUser, fallbackUID, nil
}
