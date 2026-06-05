// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyeditor"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRunYAMLPrintsVerifiedPolicyOnly(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--yaml"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--yaml) code = %d, stderr = %q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "policy OK") {
		t.Fatalf("--yaml stdout included status text:\n%s", stdout.String())
	}
	if _, err := policy.ParseStoredConfig(stdout.Bytes()); err != nil {
		t.Fatalf("--yaml stdout is not valid policy YAML: %v\n%s", err, stdout.String())
	}
}

func TestRunSHA256PrintsVerifiedPolicyDigestOnly(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	var stdout, stderr bytes.Buffer

	policyBytes, err := os.ReadFile(policy.PolicyPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}

	code := run(context.Background(), []string{"-d", dataDir, "--sha256"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--sha256) code = %d, stderr = %q", code, stderr.String())
	}
	want := policy.PolicySHA256(policyBytes) + "\n"
	if stdout.String() != want {
		t.Fatalf("--sha256 stdout = %q, want %q", stdout.String(), want)
	}
}

func TestRunSaveReadsPolicyFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	policyBytes := []byte("# saved through appolicy\nreject_foreign_rekey: false\n")
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--save"}, bytes.NewReader(policyBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--save) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy saved:") {
		t.Fatalf("--save stdout = %q, want saved status", stdout.String())
	}
	gotBytes, err := os.ReadFile(policy.PolicyPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}
	if string(gotBytes) != string(policyBytes) {
		t.Fatalf("--save changed policy bytes:\ngot:\n%s\nwant:\n%s", gotBytes, policyBytes)
	}
}

func TestRunCheckCanReadPassphraseFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--check"}, strings.NewReader(passphrase+"\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--check) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy OK:") {
		t.Fatalf("--check stdout = %q, want policy OK", stdout.String())
	}
}

func TestRunCheckPolicyFileDoesNotRequireStorePassphrase(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	t.Setenv("APSIGNER_PASSPHRASE", "")
	t.Setenv("APSIGNER_DATA", "")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("reject_foreign_rekey: false\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--check", path}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--check file) code = %d, stderr = %q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "passphrase") {
		t.Fatalf("--check file unexpectedly asked for passphrase: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy OK: "+path) {
		t.Fatalf("--check file stdout = %q, want policy OK for file", stdout.String())
	}
}

func TestRunCheckPolicyFileRejectsAttestationBlock(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	t.Setenv("APSIGNER_PASSPHRASE", "")
	t.Setenv("APSIGNER_DATA", "")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("attestation: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--check", path}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run(--check invalid attestation) code = 0, stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "policy.yaml attestation is not supported") {
		t.Fatalf("stderr = %q, want attestation block rejection", stderr.String())
	}
}

func TestRunToAttestationPolicyFilePrintsDirectAttestationYAML(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	t.Setenv("APSIGNER_PASSPHRASE", "")
	t.Setenv("APSIGNER_DATA", "")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	raw := `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: route
      networks: [testnet]
      sources: ["*"]
      assets: [algo]
      destinations: ["*"]
      limits:
        review_above: 10
        reject_above: 20
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--to-attestation", path}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--to-attestation file) code = %d, stderr = %q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "policy OK") || strings.Contains(stdout.String(), "attestation:") || strings.Contains(stdout.String(), "review_above") {
		t.Fatalf("--to-attestation stdout contains status, wrapper, or review threshold:\n%s", stdout.String())
	}
	if _, err := policy.ParseStoredAttestationConfig(stdout.Bytes()); err != nil {
		t.Fatalf("--to-attestation stdout is not valid attestation YAML: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "reject_above: 20") {
		t.Fatalf("--to-attestation stdout missing reject_above:\n%s", stdout.String())
	}
}

func TestRunSaveRejectsPolicyFileArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--save", "policy.yaml"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run(--save file) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "does not accept a file argument") {
		t.Fatalf("stderr = %q, want file argument rejection", stderr.String())
	}
}

func TestRunRejectsCombinedCLIModes(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--yaml", "--to-attestation"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run(combined modes) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "choose only one") {
		t.Fatalf("stderr = %q, want mode conflict", stderr.String())
	}
}

func initializedAppolicyStore(t *testing.T) (string, string) {
	t.Helper()
	dataDir := t.TempDir()
	passphrase := "appolicy-test-passphrase"
	_, err := storeinit.Initialize([]byte(passphrase), storeinit.Options{
		DataDir:    dataDir,
		Paths:      storepaths.NewPaths(dataDir),
		IdentityID: policyeditor.DefaultIdentityID,
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return dataDir, passphrase
}
