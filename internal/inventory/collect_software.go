package inventory

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// collectSoftware gathers packages, kernel modules, listening sockets, local accounts,
// CA certificates and USB devices. Each list is capped at the collector limit.
func (c *Collector) collectSoftware(ctx context.Context) types.SoftwareInfo {
	sw := types.SoftwareInfo{}
	sw.Packages, sw.PackageCount = c.packages(ctx)
	sw.KernelModules = c.kernelModules()
	sw.Listening = c.listeningSockets(ctx)
	sw.LocalAccounts = c.localAccounts()
	sw.CACerts = c.caCertificates()
	sw.USBDevices = c.usbDevices()
	return sw
}

// dpkgRichFormat asks dpkg-query for name, version, architecture, origin and install time.
const dpkgRichFormat = "${Package}\t${Version}\t${Architecture}\t${Origin}\n"

func (c *Collector) packages(ctx context.Context) ([]types.InventoryPackage, int) {
	out, err := c.run(ctx, "dpkg-query", "-W", "-f="+dpkgRichFormat)
	if err != nil && out == "" {
		return nil, 0
	}
	installTimes := c.packageInstallTimes()
	var pkgs []types.InventoryPackage
	total := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || strings.TrimSpace(fields[0]) == "" {
			continue
		}
		total++
		p := types.InventoryPackage{
			Name:    strings.TrimSpace(fields[0]),
			Version: strings.TrimSpace(fields[1]),
		}
		if len(fields) >= 3 {
			p.Architecture = strings.TrimSpace(fields[2])
		}
		if len(fields) >= 4 {
			p.Origin = strings.TrimSpace(fields[3])
		}
		if t, ok := installTimes[p.Name]; ok {
			p.InstallTime = t
		}
		pkgs = append(pkgs, p)
	}
	keep := c.cap(len(pkgs))
	return pkgs[:keep], total
}

// packageInstallTimes maps package name -> RFC 3339 install time from the mtime of its
// dpkg .list file, which dpkg writes when the package is unpacked. Best-effort.
func (c *Collector) packageInstallTimes() map[string]string {
	out := map[string]string{}
	dir := c.path("/var/lib/dpkg/info")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".list") {
			continue
		}
		pkg := strings.TrimSuffix(name, ".list")
		// Drop any :arch qualifier dpkg appends.
		if i := strings.IndexByte(pkg, ':'); i > 0 {
			pkg = pkg[:i]
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out[pkg] = info.ModTime().UTC().Format(time.RFC3339)
	}
	return out
}

func (c *Collector) kernelModules() []string {
	f, err := os.Open(c.path("/proc/modules"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var mods []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		mods = append(mods, fields[0])
	}
	keep := c.cap(len(mods))
	return mods[:keep]
}

// listeningSockets runs `ss -tulpnH` and parses listening TCP/UDP sockets. The process name
// is extracted from the users:(("name",pid,fd)) column.
func (c *Collector) listeningSockets(ctx context.Context) []types.ListeningSocket {
	out, err := c.run(ctx, "ss", "-tulpnH")
	if err != nil && out == "" {
		return nil
	}
	var socks []types.ListeningSocket
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]
		if len(fields) < 5 {
			continue
		}
		proto := fields[0]
		// Only listening sockets: UDP has state UNCONN, TCP has LISTEN.
		state := fields[1]
		if state != "LISTEN" && state != "UNCONN" {
			continue
		}
		local := fields[4]
		addr, port := splitHostPort(local)
		if port == 0 {
			continue
		}
		s := types.ListeningSocket{Protocol: proto, Port: port, Address: addr}
		if procField := lastField(fields, 6); procField != "" {
			s.ProcessName = parseSSProcess(procField)
		}
		socks = append(socks, s)
	}
	keep := c.cap(len(socks))
	return socks[:keep]
}

// splitHostPort splits an ss local-address column ("0.0.0.0:22", "[::]:53", "*:68").
func splitHostPort(s string) (host string, port int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0
	}
	host = strings.Trim(s[:i], "[]")
	p, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return host, 0
	}
	return host, p
}

func lastField(fields []string, idx int) string {
	if len(fields) > idx {
		return strings.Join(fields[idx:], " ")
	}
	return ""
}

// parseSSProcess pulls the first process name out of `users:(("sshd",pid=1,fd=3),...)`.
func parseSSProcess(s string) string {
	i := strings.Index(s, `(("`)
	if i < 0 {
		return ""
	}
	rest := s[i+3:]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

// localAccounts reads /etc/passwd for UID >= 1000 (and < 65534 to skip nobody) and marks
// membership in the sudo/admin groups from /etc/group. It never reads password hashes.
func (c *Collector) localAccounts() []types.LocalAccount {
	f, err := os.Open(c.path("/etc/passwd"))
	if err != nil {
		return nil
	}
	defer f.Close()
	sudoers := c.sudoMembers()
	var accts []types.LocalAccount
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil || uid < 1000 || uid >= 65534 {
			continue
		}
		user := parts[0]
		accts = append(accts, types.LocalAccount{
			Username: user,
			UID:      uid,
			IsSudo:   sudoers[user],
			Shell:    parts[6],
		})
	}
	keep := c.cap(len(accts))
	return accts[:keep]
}

// sudoMembers returns the set of usernames in the sudo or admin groups.
func (c *Collector) sudoMembers() map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(c.path("/etc/group"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 4 {
			continue
		}
		if parts[0] != "sudo" && parts[0] != "admin" {
			continue
		}
		for _, m := range strings.Split(parts[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				out[m] = true
			}
		}
	}
	return out
}

// caCertificates parses the concatenated system CA bundle and returns subject/expiry/sha256
// per certificate, metadata only. It reads the standard Debian bundle path.
func (c *Collector) caCertificates() []types.CACertificate {
	data, err := os.ReadFile(c.path("/etc/ssl/certs/ca-certificates.crt"))
	if err != nil {
		return nil
	}
	var certs []types.CACertificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		certs = append(certs, types.CACertificate{
			Subject: cert.Subject.String(),
			Expiry:  cert.NotAfter.UTC().Format(time.RFC3339),
			SHA256:  hex.EncodeToString(sum[:]),
		})
	}
	keep := c.cap(len(certs))
	return certs[:keep]
}

// usbDevices reads /sys/bus/usb/devices for devices exposing idVendor/idProduct.
func (c *Collector) usbDevices() []types.USBDevice {
	base := c.path("/sys/bus/usb/devices")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var devs []types.USBDevice
	for _, e := range entries {
		dir := filepath.Join(base, e.Name())
		vendor := readTrim(filepath.Join(dir, "idVendor"))
		product := readTrim(filepath.Join(dir, "idProduct"))
		if vendor == "" || product == "" {
			continue
		}
		name := strings.TrimSpace(readTrim(filepath.Join(dir, "manufacturer")) + " " + readTrim(filepath.Join(dir, "product")))
		devs = append(devs, types.USBDevice{VendorID: vendor, ProductID: product, Name: name})
	}
	keep := c.cap(len(devs))
	return devs[:keep]
}
