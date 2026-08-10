// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/signerprobe"
)

func TestRunSignerRunningExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		result   signerprobe.Result
		err      error
		wantExit int
		wantOut  string
		wantErr  string
		quiet    bool
	}{
		{
			name:     "running",
			result:   signerprobe.Result{State: signerprobe.StateRunning, IPCPath: "/tmp/aplane.sock"},
			wantExit: exitRunning,
			wantOut:  "running /tmp/aplane.sock",
		},
		{
			name:     "stopped",
			result:   signerprobe.Result{State: signerprobe.StateStopped, IPCPath: "/tmp/aplane.sock"},
			wantExit: exitStopped,
			wantOut:  "stopped /tmp/aplane.sock",
		},
		{
			name:     "stopped quiet",
			result:   signerprobe.Result{State: signerprobe.StateStopped, IPCPath: "/tmp/aplane.sock"},
			wantExit: exitStopped,
			quiet:    true,
		},
		{
			name:     "unknown",
			result:   signerprobe.Result{IPCPath: "/tmp/aplane.sock"},
			err:      errors.New("boom"),
			wantExit: exitUnknown,
			wantErr:  "unknown /tmp/aplane.sock",
		},
	}

	origCheck := checkSigner
	defer func() { checkSigner = origCheck }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkSigner = func(dataDir string, opts signerprobe.Options) (signerprobe.Result, error) {
				if dataDir != "/tmp/data" {
					t.Fatalf("dataDir = %q, want /tmp/data", dataDir)
				}
				if !opts.DataDirExplicit {
					t.Fatal("DataDirExplicit = false, want true for -d")
				}
				return tt.result, tt.err
			}

			args := []string{"signer-running", "-d", "/tmp/data"}
			if tt.quiet {
				args = append(args, "--quiet")
			}
			var stdout, stderr bytes.Buffer
			gotExit := run(args, &stdout, &stderr)
			if gotExit != tt.wantExit {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", gotExit, tt.wantExit, stdout.String(), stderr.String())
			}
			if tt.wantOut != "" && !strings.Contains(stdout.String(), tt.wantOut) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tt.wantOut)
			}
			if tt.wantOut == "" && stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if tt.wantErr != "" && !strings.Contains(stderr.String(), tt.wantErr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

func TestRunWithoutDataDirUsesPublicResolver(t *testing.T) {
	t.Setenv("APSIGNER_DATA", "")

	origCheck := checkSigner
	defer func() { checkSigner = origCheck }()
	checkSigner = func(dataDir string, opts signerprobe.Options) (signerprobe.Result, error) {
		if dataDir != "" {
			t.Fatalf("dataDir = %q, want empty", dataDir)
		}
		return signerprobe.Result{State: signerprobe.StateStopped, IPCPath: "/run/apsigner/aplane.sock"}, nil
	}

	var stdout, stderr bytes.Buffer
	gotExit := run([]string{"signer-running"}, &stdout, &stderr)
	if gotExit != exitStopped {
		t.Fatalf("exit = %d, want %d", gotExit, exitStopped)
	}
	if !strings.Contains(stdout.String(), "stopped /run/apsigner/aplane.sock") {
		t.Fatalf("stdout = %q, want public runtime socket", stdout.String())
	}
}

func TestRunSignerIPCPathRequiresExplicitDataDir(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"signer-ipc-path"}, &stdout, &stderr); code != exitUnknown {
		t.Fatalf("exit = %d, want %d", code, exitUnknown)
	}
	if !strings.Contains(stderr.String(), "requires -d") {
		t.Fatalf("stderr = %q, want explicit data-dir requirement", stderr.String())
	}
}

func TestRunSignerIPCPathMirrorsManagedDaemonResolution(t *testing.T) {
	externalRoot := t.TempDir()
	tests := []struct {
		name       string
		configured func(string) string
		want       func(string) string
	}{
		{
			name:       "omitted",
			configured: func(string) string { return "" },
			want:       func(string) string { return adminipc.SystemSocketPath },
		},
		{
			name: "absolute legacy default",
			configured: func(root string) string {
				return root + string(filepath.Separator) + "." + string(filepath.Separator) + "aplane.sock"
			},
			want: func(string) string { return adminipc.SystemSocketPath },
		},
		{
			name:       "relative legacy default",
			configured: func(string) string { return "aplane.sock" },
			want:       func(string) string { return adminipc.SystemSocketPath },
		},
		{
			name: "custom external path containing hash",
			configured: func(string) string {
				return filepath.Join(externalRoot, "runtime#blue", "aplane.sock")
			},
			want: func(string) string {
				return filepath.Join(externalRoot, "runtime#blue", "aplane.sock")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, ".prod"), []byte("managed\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			configured := tt.configured(root)
			config := "schema_version: 1\n"
			if configured != "" {
				config += fmt.Sprintf("ipc_path: %q\n", configured)
			}
			if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			if code := run([]string{"signer-ipc-path", "-d", root}, &stdout, &stderr); code != exitRunning {
				t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
			}
			if got, want := strings.TrimSpace(stdout.String()), tt.want(root); got != want {
				t.Fatalf("resolved path = %q, want %q", got, want)
			}
		})
	}
}
