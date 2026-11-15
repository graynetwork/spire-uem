package inventory

import (
	"bufio"
	"os"
	"strings"
)

// OSInfo is the operating system and kernel a device reports at check-in.
type OSInfo struct {
	Name   string // PRETTY_NAME from os-release, e.g. "Debian GNU/Linux 12 (bookworm)"
	Kernel string // running kernel release, e.g. "6.1.0-27-amd64"
}

// GetOSInfo reads /etc/os-release (falling back to /usr/lib/os-release) and the running
// kernel release. Fields that cannot be read are left empty.
func GetOSInfo() OSInfo {
	var info OSInfo
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if name := prettyName(p); name != "" {
			info.Name = name
			break
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	return info
}

func prettyName(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var name, id, version string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "PRETTY_NAME":
			name = v
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	if name == "" && id != "" {
		name = strings.TrimSpace(id + " " + version)
	}
	return name
}
