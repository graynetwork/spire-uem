package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spire-uem/spire-uem/internal/ipc"
	"github.com/spire-uem/spire-uem/internal/types"
)

func main() {
	socketPath := strings.TrimSpace(os.Getenv("SPIRE_SOCKET_PATH"))
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	client := newUnixHTTPClient(socketPath)
	cmd := strings.ToLower(strings.TrimSpace(os.Args[1]))

	switch cmd {
	case "status":
		if err := runStatus(client); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "sync":
		if err := runSync(client); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "catalog":
		if err := runCatalog(client); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "install":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: spire-ctl install <app-or-policy-id>")
			os.Exit(1)
		}
		target := strings.TrimSpace(os.Args[2])
		if err := runInstall(client, target); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "uninstall":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: spire-ctl uninstall <app-or-policy-id>")
			os.Exit(1)
		}
		target := strings.TrimSpace(os.Args[2])
		if err := runUninstall(client, target); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func newUnixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

func runStatus(client *http.Client) error {
	resp, err := client.Get("http://unix/v1/status")
	if err != nil {
		return fmt.Errorf("connect to spired IPC socket: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var st ipc.AgentStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return fmt.Errorf("decode status response: %w", err)
	}

	connState := "DISCONNECTED"
	if st.Connected {
		connState = "CONNECTED"
	}
	lastCheckin := "never"
	if !st.LastCheckinAt.IsZero() {
		lastCheckin = st.LastCheckinAt.Format(time.RFC3339)
	}

	fmt.Printf("SpireUEM Endpoint Agent Status\n")
	fmt.Printf("------------------------------\n")
	fmt.Printf("Hostname:         %s\n", st.Hostname)
	fmt.Printf("Hardware UUID:    %s\n", st.HardwareUUID)
	fmt.Printf("Server URL:       %s\n", st.ServerURL)
	fmt.Printf("Connection State: %s\n", connState)
	fmt.Printf("Last Check-In:    %s\n", lastCheckin)
	fmt.Printf("Compliance State: %s (%d/%d compliant, %d failed)\n",
		st.ComplianceState, st.CompliantPolicies, st.TotalPolicies, st.FailedPolicies)
	return nil
}

func runSync(client *http.Client) error {
	fmt.Println("Triggering on-demand check-in and policy reconciliation via spired...")
	resp, err := client.Post("http://unix/v1/sync", "application/json", nil)
	if err != nil {
		return fmt.Errorf("connect to spired IPC socket: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var syncResp struct {
		Status          string    `json:"status"`
		LastCheckinAt   time.Time `json:"last_checkin_at"`
		ComplianceState string    `json:"compliance_state"`
	}
	_ = json.Unmarshal(body, &syncResp)
	fmt.Printf("Sync completed successfully (status=%s, compliance=%s, checked_in_at=%s)\n",
		syncResp.Status, syncResp.ComplianceState, syncResp.LastCheckinAt.Format(time.RFC3339))
	return nil
}

func runCatalog(client *http.Client) error {
	resp, err := client.Get("http://unix/v1/catalog")
	if err != nil {
		return fmt.Errorf("connect to spired IPC socket: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("catalog fetch failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var wrapper struct {
		Catalog []types.SelfServiceCatalogItem `json:"catalog"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return fmt.Errorf("decode catalog response: %w", err)
	}

	if len(wrapper.Catalog) == 0 {
		fmt.Println("No self-service software items are currently published for this device.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "POLICY ID\tNAME\tTYPE\tINSTALLED\tDESCRIPTION")
	for _, item := range wrapper.Catalog {
		inst := "no"
		if item.Installed {
			inst = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			item.PolicyID, item.Name, item.PolicyType, inst, item.Description)
	}
	_ = tw.Flush()
	return nil
}

func runInstall(client *http.Client, target string) error {
	fmt.Printf("Requesting self-service installation of %q via spired...\n", target)
	reqBody, _ := json.Marshal(map[string]string{
		"policy_id": target,
	})
	installClient := *client
	installClient.Timeout = 15 * time.Minute
	resp, err := installClient.Post("http://unix/v1/install", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("connect to spired IPC socket: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("install failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var instResp struct {
		Status           string `json:"status"`
		PolicyID         string `json:"policy_id"`
		Name             string `json:"name"`
		PolicyType       string `json:"policy_type"`
		ComplianceStatus string `json:"compliance_status"`
	}
	_ = json.Unmarshal(body, &instResp)
	fmt.Printf("Installed %q (policy_id=%s, status=%s, compliance=%s)\n",
		instResp.Name, instResp.PolicyID, instResp.Status, instResp.ComplianceStatus)
	return nil
}

func runUninstall(client *http.Client, target string) error {
	fmt.Printf("Requesting self-service removal of %q via spired...\n", target)
	reqBody, _ := json.Marshal(map[string]string{
		"policy_id": target,
	})
	uninstallClient := *client
	uninstallClient.Timeout = 15 * time.Minute
	resp, err := uninstallClient.Post("http://unix/v1/uninstall", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("connect to spired IPC socket: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("uninstall failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var uninstResp struct {
		Status           string `json:"status"`
		PolicyID         string `json:"policy_id"`
		Name             string `json:"name"`
		PolicyType       string `json:"policy_type"`
		ComplianceStatus string `json:"compliance_status"`
	}
	_ = json.Unmarshal(body, &uninstResp)
	fmt.Printf("Uninstalled %q (policy_id=%s, status=%s)\n",
		uninstResp.Name, uninstResp.PolicyID, uninstResp.Status)
	return nil
}

func printUsage() {
	fmt.Println(`Usage: spire-ctl <command> [arguments]

Commands:
  status                       Display daemon connection state, last check-in, and compliance state
  sync                         Trigger an immediate check-in and policy reconciliation cycle
  catalog                      List available corporate self-service software for this endpoint
  install <app-or-policy-id>   Install a self-service policy/application via the spired daemon
  uninstall <app-or-policy-id> Uninstall a self-service policy/application via the spired daemon`)
}
