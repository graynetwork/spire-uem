package inventory

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// collectNetwork reads interfaces, the default gateway, DNS servers and the primary IPv4.
func (c *Collector) collectNetwork(ctx context.Context) types.NetworkInfo {
	ni := types.NetworkInfo{}

	gw, gwIface := c.defaultRoute()
	ni.DefaultGateway = gw
	ni.DNSServers = c.dnsServers()
	ni.Interfaces = c.interfaces(gwIface, &ni)
	return ni
}

func (c *Collector) interfaces(primaryIface string, ni *types.NetworkInfo) []types.NetInterface {
	base := c.path("/sys/class/net")
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []types.NetInterface
	addrs := c.interfaceAddrs()
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		dir := filepath.Join(base, name)
		iface := types.NetInterface{Name: name}
		iface.MAC = readTrim(filepath.Join(dir, "address"))
		iface.State = readTrim(filepath.Join(dir, "operstate"))
		if a, ok := addrs[name]; ok {
			iface.IPv4 = a.v4
			iface.IPv6 = a.v6
		}
		if name == primaryIface {
			if len(iface.IPv4) > 0 {
				ni.PrimaryIPv4 = iface.IPv4[0]
			}
			ni.PrimaryMAC = iface.MAC
		}
		out = append(out, iface)
	}
	return out
}

type ifaceAddrs struct {
	v4 []string
	v6 []string
}

// interfaceAddrs returns per-interface v4/v6 addresses. With a fixture root it reads
// a flat file at <root>/proc/net/if_inet (name<TAB>ip lines) so tests need no netlink;
// on the real host it uses the net package.
func (c *Collector) interfaceAddrs() map[string]ifaceAddrs {
	if c.Root != "" && c.Root != "/" {
		return c.interfaceAddrsFixture()
	}
	out := map[string]ifaceAddrs{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, in := range ifaces {
		if in.Name == "lo" {
			continue
		}
		list, err := in.Addrs()
		if err != nil {
			continue
		}
		a := ifaceAddrs{}
		for _, addr := range list {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				a.v4 = append(a.v4, v4.String())
			} else {
				a.v6 = append(a.v6, ipnet.IP.String())
			}
		}
		out[in.Name] = a
	}
	return out
}

// interfaceAddrsFixture reads a test-only "proc/net/if_inet" file: lines "<iface>\t<ip>".
func (c *Collector) interfaceAddrsFixture() map[string]ifaceAddrs {
	out := map[string]ifaceAddrs{}
	f, err := os.Open(c.path("/proc/net/if_inet"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		name, ipStr := fields[0], fields[1]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		a := out[name]
		if ip.To4() != nil {
			a.v4 = append(a.v4, ip.String())
		} else {
			a.v6 = append(a.v6, ip.String())
		}
		out[name] = a
	}
	return out
}

// defaultRoute parses /proc/net/route and returns the IPv4 default gateway and its interface.
func (c *Collector) defaultRoute() (gateway, iface string) {
	f, err := os.Open(c.path("/proc/net/route"))
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false // header
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		// Default route has Destination 00000000; Gateway is little-endian hex.
		if fields[1] != "00000000" {
			continue
		}
		gwHex := fields[2]
		if gw := leHexToIP(gwHex); gw != "" {
			return gw, fields[0]
		}
	}
	return "", ""
}

// leHexToIP converts an 8-char little-endian hex IPv4 (as in /proc/net/route) to dotted quad.
func leHexToIP(h string) string {
	if len(h) != 8 {
		return ""
	}
	n, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return ""
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(n))
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func (c *Collector) dnsServers() []string {
	f, err := os.Open(c.path("/etc/resolv.conf"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var servers []string
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[1]
		if net.ParseIP(ip) == nil {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		servers = append(servers, ip)
	}
	return servers
}
