package engine

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// DefaultDatastreamPath is the standard SSG datastream location for Debian 12.
const DefaultDatastreamPath = "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml"

// FallbackDatastreamPaths provides alternate SSG content paths on Debian fleets.
var FallbackDatastreamPaths = []string{
	"/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml",
	"/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml",
	"/usr/share/xml/scap/ssg/content/ssg-debian10-ds.xml",
}

// DefaultBenchmarkProfile is the baseline security profile used if none specified.
const DefaultBenchmarkProfile = "xccdf_org.ssgproject.content_profile_standard"

// RunBenchmarkScan evaluates system state against an OpenSCAP XCCDF profile and datastream.
func RunBenchmarkScan(ctx context.Context, profile, datastreamPath string) (*types.BenchmarkResultPayload, error) {
	oscapPath, err := exec.LookPath("oscap")
	if err != nil {
		return nil, fmt.Errorf("oscap executable not found in PATH: %w", err)
	}

	dsPath := strings.TrimSpace(datastreamPath)
	if dsPath == "" {
		dsPath = DefaultDatastreamPath
	}

	// Verify datastream existence, falling back to installed Debian versions if necessary
	if _, err := os.Stat(dsPath); err != nil {
		found := false
		for _, fallback := range FallbackDatastreamPaths {
			if _, sErr := os.Stat(fallback); sErr == nil {
				dsPath = fallback
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("datastream file not found: %s", dsPath)
		}
	}

	prof := strings.TrimSpace(profile)
	if prof == "" {
		prof = DefaultBenchmarkProfile
	}

	tmpFile := fmt.Sprintf("/tmp/oscap-results-%d-%d.xml", time.Now().UnixNano(), os.Getpid())
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	cmd := exec.CommandContext(ctx, oscapPath, "xccdf", "eval", "--profile", prof, "--results", tmpFile, dsPath)
	output, cmdErr := cmd.CombinedOutput()

	// In OpenSCAP, exit code 0 means all passed; exit code 2 means evaluation finished with test failures.
	// Both produce a valid results XML file. Exit code 1 or other indicates fatal failure.
	if cmdErr != nil {
		var exitErr *exec.ExitError
		if errors.As(cmdErr, &exitErr) {
			exitCode := exitErr.ExitCode()
			if exitCode != 0 && exitCode != 2 {
				return nil, fmt.Errorf("oscap evaluation failed with code %d: %s (output: %s)",
					exitCode, cmdErr, strings.TrimSpace(string(output)))
			}
		} else {
			return nil, fmt.Errorf("execute oscap: %w (output: %s)", cmdErr, strings.TrimSpace(string(output)))
		}
	}

	resultsFile, err := os.Open(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("open oscap results xml: %w", err)
	}
	defer resultsFile.Close()

	payload, err := ParseBenchmarkResultsXML(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("parse oscap results: %w", err)
	}

	// If all rules were marked notapplicable due to Debian 13+ CPE version mismatch against ssg-debian12-ds.xml,
	// re-evaluate with the benchmark-level platform CPE tag stripped and --skip-validation enabled.
	if payload.RulesPassed == 0 && payload.RulesFailed == 0 && payload.RulesOther > 0 {
		if rawDS, rErr := os.ReadFile(dsPath); rErr == nil {
			patchedDS := strings.ReplaceAll(string(rawDS), `<xccdf-1.2:platform idref="cpe:/o:debian:debian_linux:12"/>`, "")
			patchedDS = strings.ReplaceAll(patchedDS, `<platform idref="cpe:/o:debian:debian_linux:12"/>`, "")
			tmpDS := fmt.Sprintf("/tmp/oscap-ds-%d-%d.xml", time.Now().UnixNano(), os.Getpid())
			if wErr := os.WriteFile(tmpDS, []byte(patchedDS), 0600); wErr == nil {
				defer os.Remove(tmpDS)
				_ = resultsFile.Close()
				_ = os.Remove(tmpFile)
				cmd2 := exec.CommandContext(ctx, oscapPath, "xccdf", "eval", "--skip-validation", "--profile", prof, "--results", tmpFile, tmpDS)
				_, _ = cmd2.CombinedOutput()
				if rf2, oErr := os.Open(tmpFile); oErr == nil {
					defer rf2.Close()
					if p2, pErr := ParseBenchmarkResultsXML(rf2); pErr == nil {
						payload = p2
					}
				}
			}
		}
	}

	log.Printf("[benchmark] scan completed profile=%s score=%.2f passed=%d failed=%d other=%d",
		prof, payload.Score, payload.RulesPassed, payload.RulesFailed, payload.RulesOther)
	return payload, nil
}

// ParseBenchmarkResultsXML extracts rule counts, compliance score, and failed rules from OpenSCAP XML.
func ParseBenchmarkResultsXML(r io.Reader) (*types.BenchmarkResultPayload, error) {
	decoder := xml.NewDecoder(r)

	var (
		passedCount  int
		failedCount  int
		otherCount   int
		scoreVal     float64
		hasScore     bool
		failedRules  []types.FailedRuleItem
	)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("xml parse error: %w", err)
		}

		switch elem := token.(type) {
		case xml.StartElement:
			localName := elem.Name.Local
			switch localName {
			case "score":
				var scoreStr string
				if err := decoder.DecodeElement(&scoreStr, &elem); err == nil {
					scoreStr = strings.TrimSpace(scoreStr)
					if val, parseErr := strconv.ParseFloat(scoreStr, 64); parseErr == nil {
						scoreVal = val
						hasScore = true
					}
				}

			case "rule-result":
				var idRef, severity string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "idref" {
						idRef = attr.Value
					} else if attr.Name.Local == "severity" {
						severity = attr.Value
					}
				}

				resultText := parseRuleResultText(decoder)
				switch strings.ToLower(resultText) {
				case "pass":
					passedCount++
				case "fail":
					failedCount++
					failedRules = append(failedRules, types.FailedRuleItem{
						RuleID:   idRef,
						Title:    formatRuleTitle(idRef),
						Result:   "fail",
						Severity: severity,
					})
				default:
					otherCount++
				}
			}
		}
	}

	// Calculate score if not explicitly parsed from xml or if CPE platform mismatch produced 0.0
	totalEvaluated := passedCount + failedCount
	if (!hasScore || scoreVal == 0) && totalEvaluated > 0 {
		scoreVal = (float64(passedCount) / float64(totalEvaluated)) * 100.0
	}

	return &types.BenchmarkResultPayload{
		Status:      "COMPLETED",
		Score:       scoreVal,
		RulesPassed: passedCount,
		RulesFailed: failedCount,
		RulesOther:  otherCount,
		FailedRules: failedRules,
	}, nil
}

func parseRuleResultText(decoder *xml.Decoder) string {
	depth := 1
	var resultText string
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if t.Name.Local == "result" {
				var text string
				if err := decoder.DecodeElement(&text, &t); err == nil {
					resultText = strings.TrimSpace(text)
					depth-- // DecodeElement consumed the EndElement
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	return resultText
}

// formatRuleTitle converts a SCAP rule ID like 'xccdf_org.ssgproject.content_rule_sysctl_fs_protected_hardlinks'
// into a clean title like 'Sysctl fs protected hardlinks'.
func formatRuleTitle(idref string) string {
	clean := idref
	prefixes := []string{
		"xccdf_org.ssgproject.content_rule_",
		"xccdf_org.open-scap_rule_",
		"rule_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(clean, p) {
			clean = strings.TrimPrefix(clean, p)
			break
		}
	}
	clean = strings.ReplaceAll(clean, "_", " ")
	clean = strings.ReplaceAll(clean, "-", " ")
	if len(clean) > 0 {
		clean = strings.ToUpper(clean[:1]) + clean[1:]
	}
	return clean
}
