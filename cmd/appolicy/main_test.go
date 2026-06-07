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

	"github.com/aplane-algo/aplane/internal/noderole"
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

func TestRunSavePolicyReadsPolicyFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	policyBytes := []byte("# saved through appolicy\nreject_foreign_rekey: false\n")
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--save-policy"}, bytes.NewReader(policyBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--save-policy) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy saved:") {
		t.Fatalf("--save-policy stdout = %q, want saved status", stdout.String())
	}
	gotBytes, err := os.ReadFile(policy.PolicyPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}
	if string(gotBytes) != string(policyBytes) {
		t.Fatalf("--save-policy changed policy bytes:\ngot:\n%s\nwant:\n%s", gotBytes, policyBytes)
	}
}

func TestRunSaveAttestationReadsAttestationFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	attestationBytes := []byte(`# saved through appolicy
reject_rekey: true
transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: allow_algo
      networks: [testnet]
      sources: ["*"]
      assets: [algo]
      destinations: ["*"]
`)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--save-attestation"}, bytes.NewReader(attestationBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--save-attestation) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "attestation policy saved:") {
		t.Fatalf("--save-attestation stdout = %q, want saved status", stdout.String())
	}
	gotBytes, err := os.ReadFile(policy.AttestationPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(attestation) error = %v", err)
	}
	if string(gotBytes) != string(attestationBytes) {
		t.Fatalf("--save-attestation changed attestation bytes:\ngot:\n%s\nwant:\n%s", gotBytes, attestationBytes)
	}
	if _, err := policy.ParseStoredAttestationConfig(gotBytes); err != nil {
		t.Fatalf("saved attestation YAML does not parse: %v", err)
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

func TestRunSavePolicyAliasReadsPolicyFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	policyBytes := []byte("reject_foreign_rekey: false\n")
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--save"}, bytes.NewReader(policyBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--save alias) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy saved:") {
		t.Fatalf("--save alias stdout = %q, want policy saved status", stdout.String())
	}
}

func TestRunSaveAutoTargetsAttestationOnAttestorNode(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStoreWithRole(t, noderole.RoleAttestor)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	attestationBytes := []byte("reject_rekey: true\n")
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--save"}, bytes.NewReader(attestationBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(attestor --save) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "attestation policy saved:") {
		t.Fatalf("attestor --save stdout = %q, want attestation saved status", stdout.String())
	}
	gotBytes, err := os.ReadFile(policy.AttestationPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(attestation) error = %v", err)
	}
	if string(gotBytes) != string(attestationBytes) {
		t.Fatalf("attestation bytes changed during auto --save:\ngot:\n%s\nwant:\n%s", gotBytes, attestationBytes)
	}
}

func TestRunYAMLAutoTargetsAttestationOnAttestorNode(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStoreWithRole(t, noderole.RoleAttestor)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	attestationBytes := []byte("reject_rekey: true\n")
	var saveOut, saveErr bytes.Buffer
	if code := run(context.Background(), []string{"-d", dataDir, "--save"}, bytes.NewReader(attestationBytes), &saveOut, &saveErr); code != 0 {
		t.Fatalf("run(attestor --save) code = %d, stderr = %q", code, saveErr.String())
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--yaml"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(attestor --yaml) code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != string(attestationBytes) {
		t.Fatalf("attestor --yaml stdout:\ngot:\n%s\nwant:\n%s", stdout.String(), attestationBytes)
	}
	if _, err := policy.ParseStoredAttestationConfig(stdout.Bytes()); err != nil {
		t.Fatalf("attestor --yaml stdout is not valid attestation YAML: %v\n%s", err, stdout.String())
	}
}

func TestRunTargetOverrideCanReadSignerPolicyOnAttestorNode(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStoreWithRole(t, noderole.RoleAttestor)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--target", "signer", "--yaml"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--target signer --yaml) code = %d, stderr = %q", code, stderr.String())
	}
	if _, err := policy.ParseStoredConfig(stdout.Bytes()); err != nil {
		t.Fatalf("--target signer stdout is not valid signer policy YAML: %v\n%s", err, stdout.String())
	}
}

func TestRunSaveRejectsPolicyFileArgument(t *testing.T) {
	for _, flag := range []string{"--save", "--save-policy", "--save-attestation"} {
		t.Run(flag, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(context.Background(), []string{flag, "policy.yaml"}, strings.NewReader(""), &stdout, &stderr)
			if code != 2 {
				t.Fatalf("run(%s file) code = %d, want 2", flag, code)
			}
			if !strings.Contains(stderr.String(), "does not accept a file argument") {
				t.Fatalf("stderr = %q, want file argument rejection", stderr.String())
			}
		})
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
	return initializedAppolicyStoreWithRole(t, noderole.RoleSigner)
}

func initializedAppolicyStoreWithRole(t *testing.T, role noderole.Role) (string, string) {
	t.Helper()
	dataDir := t.TempDir()
	passphrase := "appolicy-test-passphrase"
	_, err := storeinit.Initialize([]byte(passphrase), storeinit.Options{
		DataDir:    dataDir,
		Paths:      storepaths.NewPaths(dataDir),
		IdentityID: policyeditor.DefaultIdentityID,
		Role:       role,
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return dataDir, passphrase
}
