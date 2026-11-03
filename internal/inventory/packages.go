package inventory

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// GetInstalledPackages runs dpkg-query -W -f='${Package}\t${Version}\n' and parses the output into a string slice.
func GetInstalledPackages() ([]string, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query failed: %w", err)
	}

	var packages []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		packages = append(packages, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan dpkg-query output: %w", err)
	}
	return packages, nil
}
