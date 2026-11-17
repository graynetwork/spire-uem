package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// runScriptDirectives executes each script directive the server dispatched and reports the
// outcomes in one batch. Older servers never send these, so an empty slice is a no-op.
func runScriptDirectives(ctx context.Context, client *http.Client, serverURL, token, hwUUID string, directives []types.ScriptDirective) {
	if len(directives) == 0 {
		return
	}
	runner := engine.NewScriptRunner("")
	results := make([]types.ScriptRunResult, 0, len(directives))
	for _, d := range directives {
		log.Printf("[spired] running script directive run=%s version=%d interp=%s run_as=%s", d.RunID, d.Version, d.Interpreter, d.RunAs)
		res := runner.RunScriptResult(ctx, d)
		log.Printf("[spired] script run=%s status=%s exit=%d dur=%dms", d.RunID, res.Status, res.ExitCode, res.DurationMS)
		results = append(results, res)
	}
	if err := postJSON(ctx, client, serverURL+"/api/v1/desktop/scripts/report", token, types.ScriptRunReport{
		HardwareUUID: hwUUID, Runs: results,
	}); err != nil {
		log.Printf("[spired] failed to report %d script run(s): %v", len(results), err)
	}
}

// runSensorDirectives runs each due sensor's script, parses nothing locally (the server types
// the trimmed stdout), and reports the raw value + exit code in a batch.
func runSensorDirectives(ctx context.Context, client *http.Client, serverURL, token, hwUUID string, directives []types.SensorDirective) {
	if len(directives) == 0 {
		return
	}
	runner := engine.NewScriptRunner("")
	results := make([]types.SensorResultReport, 0, len(directives))
	for _, d := range directives {
		log.Printf("[spired] running sensor %s version=%d return=%s", d.SensorName, d.Version, d.ReturnType)
		out := runner.RunSensorResult(ctx, d)
		rep := types.SensorResultReport{
			SensorName: d.SensorName,
			ExitCode:   out.ExitCode,
			RawValue:   out.Stdout,
			DurationMS: out.DurationMS,
		}
		if out.Status != types.ScriptRunCompleted || out.ExitCode != 0 {
			rep.Error = strings.TrimSpace(out.Stderr)
			if rep.Error == "" {
				rep.Error = "sensor did not complete (" + string(out.Status) + ")"
			}
		}
		results = append(results, rep)
	}
	if err := postJSON(ctx, client, serverURL+"/api/v1/desktop/sensors/report", token, types.SensorReport{
		HardwareUUID: hwUUID, Results: results,
	}); err != nil {
		log.Printf("[spired] failed to report %d sensor result(s): %v", len(results), err)
	}
}

// postJSON posts a JSON body to a desktop endpoint with the bearer token and checks for 200.
func postJSON(ctx context.Context, client *http.Client, url, token string, body any) error {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return &httpStatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	return nil
}

type httpStatusError struct {
	Code int
	Body string
}

func (e *httpStatusError) Error() string {
	return "HTTP " + http.StatusText(e.Code) + ": " + e.Body
}
