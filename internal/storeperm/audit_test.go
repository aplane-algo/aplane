// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

func TestAuditAcceptsPrivateStore(t *testing.T) {
	root := privateStoreFixture(t)
	findings, err := Audit(ownerOptions(t, root, PrivateServiceProfile))
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if storeFindings := withoutAncestorFindings(findings); len(storeFindings) != 0 {
		t.Fatalf("Audit() store findings = %+v, want none", storeFindings)
	}
}

func TestAuditReportsUnsafeModeOwnerSymlinkAndHardlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership and hardlink contract")
	}
	root := privateStoreFixture(t)
	identityDir := filepath.Join(root, "identities", "default")
	policyPath := filepath.Join(identityDir, "policy.yaml")
	if err := os.Chmod(identityDir, 0o770); err != nil {
		t.Fatalf("Chmod(identityDir): %v", err)
	}
	if err := os.Link(policyPath, filepath.Join(identityDir, "policy-copy")); err != nil {
		t.Fatalf("Link: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("WriteFile(outside): %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(identityDir, "planted")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	opts := ownerOptions(t, root, PrivateServiceProfile)
	opts.ExpectedUID++
	findings, err := Audit(opts)
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	for _, code := range []string{"mode", "owner", "hardlink", "symlink"} {
		if !hasFindingCode(findings, code) {
			t.Fatalf("Audit() findings = %+v, want code %q", findings, code)
		}
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "outside" {
		t.Fatalf("outside target changed: data=%q err=%v", data, err)
	}
}

func TestAuditAcceptsNarrowRootCredentialException(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned fixture")
	}
	root := privateStoreFixture(t)
	cred := filepath.Join(root, "identities", "default", "passphrase.cred")
	if err := os.WriteFile(cred, []byte("encrypted"), 0o600); err != nil {
		t.Fatalf("WriteFile(cred): %v", err)
	}
	if err := os.Chown(cred, 0, 0); err != nil {
		t.Fatalf("Chown(cred): %v", err)
	}
	findings, err := Audit(ownerOptions(t, root, PrivateServiceProfile))
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if storeFindings := withoutAncestorFindings(findings); len(storeFindings) != 0 {
		t.Fatalf("Audit() store findings = %+v, want none", storeFindings)
	}
}

func TestAuditLegacyProfileAcceptsSetgidSharedLayout(t *testing.T) {
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o770|os.ModeSetgid); err != nil {
		t.Fatalf("Chmod(root): %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte("x"), 0o660); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	findings, err := Audit(ownerOptions(t, root, LegacySharedProfile))
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if storeFindings := withoutAncestorFindings(findings); len(storeFindings) != 0 {
		t.Fatalf("Audit() store findings = %+v, want none", storeFindings)
	}
}

func TestMigratePrivateClampsModesAndPreservesCredentialOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership contract")
	}
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Join(root, "identities", "default")
	if err := os.MkdirAll(identityDir, 0o770); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(root, "identities"), identityDir} {
		if err := os.Chmod(dir, 0o770|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(identityDir, "policy.yaml"), []byte("policy"), 0o660); err != nil {
		t.Fatal(err)
	}
	expectedEntries := 4
	if os.Geteuid() == 0 {
		cred := filepath.Join(identityDir, "passphrase.cred")
		if err := os.WriteFile(cred, []byte("encrypted"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(cred, 0, 0); err != nil {
			t.Fatal(err)
		}
		expectedEntries++
	}

	opts := ownerOptions(t, root, LegacySharedProfile)
	opts.AncestorBoundary = filepath.Dir(root)
	result, err := MigratePrivate(opts)
	if err != nil {
		t.Fatalf("MigratePrivate() error = %v", err)
	}
	if result.Inspected != expectedEntries || result.Changed == 0 {
		t.Fatalf("MigratePrivate() result = %+v", result)
	}
	opts.Profile = PrivateServiceProfile
	findings, err := Audit(opts)
	if err != nil || len(findings) != 0 {
		t.Fatalf("private Audit() findings = %+v, err = %v", findings, err)
	}
	second, err := MigratePrivate(opts)
	if err != nil {
		t.Fatalf("second MigratePrivate() error = %v", err)
	}
	if second.Changed != 0 {
		t.Fatalf("second MigratePrivate() changed = %d, want 0", second.Changed)
	}
}

func TestMigratePrivateRejectsStructuralObjectsBeforeChangingRoot(t *testing.T) {
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(workspaceTempDir(t), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "planted")); err != nil {
		t.Fatal(err)
	}

	opts := ownerOptions(t, root, LegacySharedProfile)
	opts.AncestorBoundary = filepath.Dir(root)
	if _, err := MigratePrivate(opts); err == nil {
		t.Fatal("MigratePrivate() error = nil, want structural rejection")
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o770 || info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("root mode changed before preflight completed: %v", info.Mode())
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "outside" {
		t.Fatalf("outside file changed: %q, %v", data, err)
	}
}

func privateStoreFixture(t *testing.T) string {
	t.Helper()
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod(root): %v", err)
	}
	identityDir := filepath.Join(root, "identities", "default")
	if err := os.MkdirAll(identityDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(identityDir): %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "identities"), 0o700); err != nil {
		t.Fatalf("Chmod(identities): %v", err)
	}
	if err := os.WriteFile(filepath.Join(identityDir, "policy.yaml"), []byte("policy"), 0o600); err != nil {
		t.Fatalf("WriteFile(policy): %v", err)
	}
	return root
}

func workspaceTempDir(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp(".", ".storeperm-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatalf("Abs(temp dir): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func ownerOptions(t *testing.T, root string, profile Profile) Options {
	t.Helper()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("Stat(root): %v", err)
	}
	uid, gid, ok := fsutil.FileOwnership(info)
	if !ok {
		t.Skip("ownership metadata unavailable")
	}
	return Options{Root: root, ExpectedUID: uid, ExpectedGID: gid, Profile: profile}
}

func hasFindingCode(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func withoutAncestorFindings(findings []Finding) []Finding {
	filtered := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Code != "ancestor-write" {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}
