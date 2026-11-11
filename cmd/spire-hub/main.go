package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
)

//go:embed spire-hub.py
var hubScript string

func main() {
	pythonBin, err := exec.LookPath("python3")
	if err != nil {
		fmt.Fprintf(os.Stderr, "spire-hub: python3 executable not found in PATH: %v\n", err)
		os.Exit(1)
	}

	var args []string
	const installedScript = "/usr/lib/spire/spire-hub.py"
	if _, statErr := os.Stat(installedScript); statErr == nil {
		args = append([]string{installedScript}, os.Args[1:]...)
	} else {
		progName := os.Args[0]
		args = append([]string{"-c", hubScript, progName}, os.Args[1:]...)
	}

	cmd := exec.Command(pythonBin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "spire-hub: %v\n", err)
		os.Exit(1)
	}
}
