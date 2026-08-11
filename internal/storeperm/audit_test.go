// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeperm

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

func TestAuditAcceptsPrivateStore(t *testing.T) {
	root := privateStoreFixture(t)
	findings, err := Audit(ownerOptions(t, root, privateServiceProfile))
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if storeFindings := withoutAncestorFindings(findings); len(storeFindings) != 0 {
		t.Fatalf("Audit() store findings = %+v, want none", storeFindings)
	}
}

func TestSameUIDAuditAcceptsExactLiveSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket contract")
	}
	root := privateStoreFixture(t)
	socketPath := filepath.Join(root, "aplane.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}
	uid, gid := ownerIDs(t, root)

	findings, err := Audit(SameUIDAuditOptions(root, uid, gid, socketPath))
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if storeFindings := withoutAncestorFindings(findings); len(storeFindings) != 0 {
		t.Fatalf("same-UID Audit() store findings = %+v, want none", storeFindings)
	}
}

func TestSameUIDAuditAcceptsLocalInstalledBinaries(t *testing.T) {
	root := privateStoreFixture(t)
	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "apsigner"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := ownerIDs(t, root)

	findings, err := Audit(SameUIDAuditOptions(root, uid, gid, ""))
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if storeFindings := withoutAncestorFindings(findings); len(storeFindings) != 0 {
		t.Fatalf("same-UID Audit() store findings = %+v, want none", storeFindings)
	}
}

func TestSameUIDAuditAcceptsTrustedStickyTempAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix temporary-directory contract")
	}
	tempRoot := "/tmp"
	info, err := os.Lstat(tempRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSticky == 0 {
		t.Skip("/tmp is not a real sticky temporary directory")
	}
	filesystemRootInfo, err := os.Lstat(string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	tempUID, _, tempOwnerOK := fsutil.FileOwnership(info)
	rootUID, _, rootOwnerOK := fsutil.FileOwnership(filesystemRootInfo)
	if !tempOwnerOK || !rootOwnerOK || tempUID != rootUID {
		t.Skip("/tmp is not owned by the filesystem-root owner")
	}

	root, err := os.MkdirTemp(tempRoot, "aplane-storeperm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	populatePrivateStoreFixture(t, root)
	uid, gid := ownerIDs(t, root)

	findings, err := Audit(SameUIDAuditOptions(root, uid, gid, ""))
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Audit() findings = %+v, want trusted sticky /tmp accepted", findings)
	}
}

func TestAuditAncestorsRejectsUnrelatedOwner(t *testing.T) {
	root := workspaceTempDir(t)
	parent := filepath.Dir(root)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	filesystemRootInfo, err := os.Lstat(string(filepath.Separator))
	if err != nil {
		t.Fatal(err)
	}
	parentUID, _, parentOwnerOK := fsutil.FileOwnership(parentInfo)
	rootUID, _, rootOwnerOK := fsutil.FileOwnership(filesystemRootInfo)
	if !parentOwnerOK || !rootOwnerOK || parentUID == rootUID {
		t.Skip("test requires a non-root-owned workspace parent")
	}

	findings, err := auditAncestors(root, "", parentUID+1)
	if err != nil {
		t.Fatalf("auditAncestors() error = %v", err)
	}
	if !hasFindingCode(findings, "ancestor-owner") {
		t.Fatalf("auditAncestors() findings = %+v, want unrelated-owner rejection", findings)
	}
}

func TestMigratePrivateRejectsStoreLocalBinariesWithoutMutation(t *testing.T) {
	root := privateStoreFixture(t)
	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(binDir, "apsigner")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := ownerIDs(t, root)

	_, err := MigratePrivate(LegacyMigrationOptions(root, uid, gid, ""))
	if err == nil || !strings.Contains(err.Error(), "store-local bin directory") {
		t.Fatalf("MigratePrivate() error = %v, want local binary rejection", err)
	}
	info, statErr := os.Stat(binaryPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("binary mode after rejected migration = %04o, want 0755", got)
	}
}

func TestMigrationEntryLessIsStrictForRoot(t *testing.T) {
	root := "/store"
	rootEntry := migrationEntry{path: root}
	childEntry := migrationEntry{path: filepath.Join(root, "identities")}
	if migrationEntryLess(root, rootEntry, rootEntry) {
		t.Fatal("migrationEntryLess(root, root) = true, want strict ordering")
	}
	if !migrationEntryLess(root, rootEntry, childEntry) {
		t.Fatal("migrationEntryLess(root, child) = false, want root first")
	}
	if migrationEntryLess(root, childEntry, rootEntry) {
		t.Fatal("migrationEntryLess(child, root) = true, want root first")
	}
}

func TestProductionAuditRejectsInStoreSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket contract")
	}
	root := privateStoreFixture(t)
	socketPath := filepath.Join(root, "aplane.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	uid, gid := ownerIDs(t, root)

	findings, err := Audit(ProductionAuditOptions(root, uid, gid))
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if !hasFindingCode(findings, "type") {
		t.Fatalf("production Audit() findings = %+v, want socket type rejection", findings)
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

	opts := ownerOptions(t, root, privateServiceProfile)
	opts.policy.expectedUID++
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
	findings, err := Audit(ownerOptions(t, root, privateServiceProfile))
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
	findings, err := Audit(ownerOptions(t, root, legacySharedProfile))
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

	opts := ownerMigrationOptions(t, root, "")
	result, err := MigratePrivate(opts)
	if err != nil {
		t.Fatalf("MigratePrivate() error = %v", err)
	}
	if result.Inspected != expectedEntries || result.Changed == 0 {
		t.Fatalf("MigratePrivate() result = %+v", result)
	}
	privateOpts := ownerOptions(t, root, privateServiceProfile)
	privateOpts.policy.ancestorBoundary = filepath.Dir(root)
	findings, err := Audit(privateOpts)
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

func TestMigratePrivateExplainsUnsafeAncestorIsNotRepairable(t *testing.T) {
	boundary := workspaceTempDir(t)
	unsafeAncestor := filepath.Join(boundary, "shared")
	root := filepath.Join(unsafeAncestor, "store")
	if err := os.MkdirAll(root, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeAncestor, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	uid, gid := ownerIDs(t, root)
	opts := MigrationOptions{policy: options{
		root: root, expectedUID: uid, expectedGID: gid,
		profile: legacySharedProfile, ancestorBoundary: boundary,
	}}

	_, err := MigratePrivate(opts)
	if err == nil || !strings.Contains(err.Error(), unsafeAncestor) ||
		!strings.Contains(err.Error(), "repaired outside permissions migration") {
		t.Fatalf("MigratePrivate() error = %v, want manual ancestor repair guidance", err)
	}
	info, statErr := os.Stat(root)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o770 {
		t.Fatalf("root mode after rejected migration = %04o, want 0770", got)
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

	opts := ownerMigrationOptions(t, root, "")
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

func TestMigratePrivateRemovesRecognizedLegacySocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket contract")
	}
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "aplane.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	opts := ownerMigrationOptions(t, root, socketPath)
	result, err := MigratePrivate(opts)
	if err != nil {
		t.Fatalf("MigratePrivate() error = %v", err)
	}
	if result.Changed == 0 {
		t.Fatalf("MigratePrivate() result = %+v, want socket removal", result)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("legacy socket remains after migration: %v", err)
	}
}

func TestRecognizedLegacySocketRejectsStoreRoot(t *testing.T) {
	root := workspaceTempDir(t)
	if _, err := recognizedLegacySocket(root, root); err == nil {
		t.Fatal("recognizedLegacySocket(root) error = nil, want confinement rejection")
	}
}

func TestMigratePrivateRejectsUnrecognizedSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket contract")
	}
	root := workspaceTempDir(t)
	if err := os.Chmod(root, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "unexpected.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	opts := ownerMigrationOptions(t, root, "")
	if _, err := MigratePrivate(opts); err == nil {
		t.Fatal("MigratePrivate() error = nil, want unrecognized socket rejection")
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o770 || info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("root mode changed before socket rejection: %v", info.Mode())
	}
}

func privateStoreFixture(t *testing.T) string {
	t.Helper()
	root := workspaceTempDir(t)
	populatePrivateStoreFixture(t, root)
	return root
}

func populatePrivateStoreFixture(t *testing.T, root string) {
	t.Helper()
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

func ownerOptions(t *testing.T, root string, profile profile) AuditOptions {
	t.Helper()
	uid, gid := ownerIDs(t, root)
	return AuditOptions{policy: options{
		root: root, expectedUID: uid, expectedGID: gid, profile: profile,
	}}
}

func ownerMigrationOptions(t *testing.T, root, socketPath string) MigrationOptions {
	t.Helper()
	uid, gid := ownerIDs(t, root)
	return MigrationOptions{policy: options{
		root: root, expectedUID: uid, expectedGID: gid,
		profile: legacySharedProfile, socketPath: socketPath,
		ancestorBoundary: filepath.Dir(root),
	}}
}

func ownerIDs(t *testing.T, root string) (int, int) {
	t.Helper()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("Stat(root): %v", err)
	}
	uid, gid, ok := fsutil.FileOwnership(info)
	if !ok {
		t.Skip("ownership metadata unavailable")
	}
	return uid, gid
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
