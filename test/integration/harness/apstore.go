// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ApStoreHarness manages apstore CLI testing against a specific signer data directory.
type ApStoreHarness struct {
	t          *testing.T
	dataDir    string
	buildDir   string
	binaryPath string
}

// NewApStoreHarness creates a new apstore CLI test harness.
func NewApStoreHarness(t *testing.T, dataDir string) *ApStoreHarness {
	buildDir := filepath.Join(t.TempDir(), "apstore-build")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		t.Fatalf("Failed to create build directory: %v", err)
	}

	return &ApStoreHarness{
		t:        t,
		dataDir:  dataDir,
		buildDir: buildDir,
	}
}

// Build compiles apstore if needed.
func (a *ApStoreHarness) Build() error {
	binaryPath := filepath.Join(a.buildDir, "apstore")
	a.binaryPath = binaryPath

	if _, err := os.Stat(binaryPath); err == nil {
		return nil
	}

	projectRoot, err := findProjectRoot()
	if err != nil {
		return fmt.Errorf("failed to find project root: %w", err)
	}

	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/apstore")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build apstore: %w\nOutput: %s", err, output)
	}

	return nil
}

// RunWithInput executes an apstore command with stdin input.
func (a *ApStoreHarness) RunWithInput(input string, args ...string) (string, error) {
	if err := a.Build(); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmdArgs := append([]string{"-d", a.dataDir}, args...)
	cmd := exec.CommandContext(ctx, a.binaryPath, cmdArgs...)
	cmd.Dir = a.dataDir
	cmd.Env = append(os.Environ(), fmt.Sprintf("APSIGNER_DATA=%s", a.dataDir))

	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if testing.Verbose() {
		if stdout.Len() > 0 {
			a.t.Logf("apstore stdout: %s", stdout.String())
		}
		if stderr.Len() > 0 {
			a.t.Logf("apstore stderr: %s", stderr.String())
		}
	}

	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n" + stderr.String()
	}

	if err != nil {
		return output, fmt.Errorf("apstore command failed: %w\nOutput: %s", err, output)
	}

	return output, nil
}
