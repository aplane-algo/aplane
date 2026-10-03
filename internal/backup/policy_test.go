// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/fsutil"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func cosignerPolicyDocForBackupTest(selector, description string) []byte {
	return []byte(`{"format": "aplane.cosigner-policy.v1", "key": "` + selector + `", "description": "` + description + `", "transfer_policy": {"routes": []}}`)
}

// cosignerStoreWithPolicy returns a cosigner store holding one witness key
// with a policy document.
func cosignerStoreWithPolicy(t *testing.T) (storepaths.Paths, string, []byte) {
	t.Helper()
	paths := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	selector, keyJSON := testCosignerComponentBackupKeyJSON(t)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	encrypted, err := kr.Seal(keyJSON, crypto.CosignerCredentialContext(selector))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apkeys.CosignerCredentialFilePath(paths, selector), encrypted, fsutil.StoreFilePerm); err != nil {
		t.Fatal(err)
	}
	if _, _, err := noderole.SaveInitial(paths, noderole.RoleCosigner, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	doc := cosignerPolicyDocForBackupTest(selector, "source")
	if err := policy.WriteCosignerPolicy(activePathsForBackupTest(t, paths), selector, doc, kr, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	return paths, selector, doc
}

func TestBackupCarriesCosignerPolicyEncryptedAndVerified(t *testing.T) {
	paths, selector, doc := cosignerStoreWithPolicy(t)
	archivePath := BuildManagedArchivePath(paths, "20260721-010203")
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleCosigner, cryptotest.Keyring(t, testExportMasterKey))); err != nil {
		t.Fatalf("CreateKeysArchive() error = %v", err)
	}
	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(extractDir, "policies", selector+".apb")
	sealed, err := os.ReadFile(member)
	if err != nil {
		t.Fatalf("archived policy missing: %v", err)
	}
	if bytes.Contains(sealed, []byte("aplane.cosigner-policy.v1")) {
		t.Fatal("archived policy is stored in plaintext")
	}
	report, err := DeepVerifyBackupBytes(extractDir, []byte("export-passphrase"))
	if err != nil || report.FailedFiles != 0 || report.TotalFiles != 2 {
		t.Fatalf("DeepVerifyBackupBytes() = %+v, %v; want the credential and its policy valid", report, err)
	}

	set, err := LoadManagedRestoreSet(paths, archivePath, nil, []byte("export-passphrase"), noderole.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	defer set.ZeroSecrets()
	if len(set.Entries) != 1 || !bytes.Equal(set.Entries[0].Policy, doc) {
		t.Fatalf("restore entry policy = %q, want the exact source document", set.Entries[0].Policy)
	}

	// Tampering with the policy member breaks the sealed manifest.
	if err := os.WriteFile(member, append(sealed, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSealedManifest(extractDir, []byte("export-passphrase")); err == nil {
		t.Fatal("a modified archived policy passed manifest verification")
	}
}

func TestClassifyRestorePolicyAgainstDestination(t *testing.T) {
	paths, selector, doc := cosignerStoreWithPolicy(t)
	archivePath := BuildManagedArchivePath(paths, "20260721-010204")
	kr := cryptotest.Keyring(t, testExportMasterKey)
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleCosigner, kr)); err != nil {
		t.Fatal(err)
	}
	set, err := LoadManagedRestoreSet(paths, archivePath, nil, []byte("export-passphrase"), noderole.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	defer set.ZeroSecrets()
	active := activePathsForBackupTest(t, paths)

	same, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(same.Identical) != 1 || len(same.Policies) != 0 || len(same.Conflicts) != 0 {
		t.Fatalf("identical key and policy: %+v, %v", same, err)
	}

	if err := policy.RemoveCosignerPolicy(active, selector); err != nil {
		t.Fatal(err)
	}
	missing, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(missing.Identical) != 1 || len(missing.Policies) != 1 || len(missing.Conflicts) != 0 {
		t.Fatalf("destination without a policy: %+v, %v", missing, err)
	}
	if err := ApplyPolicyEntry(active, missing.Policies[0], kr); err != nil {
		t.Fatal(err)
	}
	if stored, ok, err := policy.LoadVerifiedCosignerPolicy(active, selector, kr); err != nil || !ok || !bytes.Equal(stored.Bytes, doc) {
		t.Fatalf("installed policy = %q, %v, %v", stored.Bytes, ok, err)
	}

	if err := policy.WriteCosignerPolicy(active, selector, cosignerPolicyDocForBackupTest(selector, "destination"), kr, timeForBackupTest()); err != nil {
		t.Fatal(err)
	}
	differs, err := ClassifyRestoreSet(active, set, kr)
	if err != nil || len(differs.Policies) != 1 || len(differs.Conflicts) != 1 ||
		!strings.Contains(differs.Conflicts[0].Reason, "existing policy differs") {
		t.Fatalf("destination with a different policy: %+v, %v", differs, err)
	}
}

func TestPartialBackupCarriesOnlySelectedPolicies(t *testing.T) {
	paths, selector, _ := cosignerStoreWithPolicy(t)
	kr := cryptotest.Keyring(t, testExportMasterKey)
	exported, err := exportCosignerPolicies(activePathsForBackupTest(t, paths), t.TempDir(), nil, kr, []byte("export-passphrase"))
	if err != nil || len(exported) != 0 {
		t.Fatalf("export with no selected keys = %v, %v", exported, err)
	}
	stage := t.TempDir()
	if exported, err = exportCosignerPolicies(activePathsForBackupTest(t, paths), stage, []string{selector}, kr, []byte("export-passphrase")); err != nil || len(exported) != 1 {
		t.Fatalf("export of the selected key = %v, %v", exported, err)
	}
}

func TestDeepVerifyRejectsPolicyWithoutCredential(t *testing.T) {
	paths, selector, _ := cosignerStoreWithPolicy(t)
	archivePath := BuildManagedArchivePath(paths, "20260721-010205")
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleCosigner, cryptotest.Keyring(t, testExportMasterKey))); err != nil {
		t.Fatal(err)
	}
	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatal(err)
	}
	result := verifyPolicyDeep(filepath.Join(extractDir, "apb"), selector, []byte("export-passphrase"), nil)
	if result.Valid || !strings.Contains(result.Error, "no cosigner credential") {
		t.Fatalf("verifyPolicyDeep(without credential) = %+v", result)
	}
}

func TestRestorerInstallsArchivedPolicyForRebuild(t *testing.T) {
	paths, selector, doc := cosignerStoreWithPolicy(t)
	archivePath := BuildManagedArchivePath(paths, "20260721-010206")
	kr := cryptotest.Keyring(t, testExportMasterKey)
	if _, err := CreateKeysArchive(testCreateKeysArchiveRequest(paths, archivePath, nil, noderole.RoleCosigner, kr)); err != nil {
		t.Fatal(err)
	}
	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatal(err)
	}

	dest := mintFirstGenerationForBackupTest(t, storepaths.NewPaths(t.TempDir()))
	destActive := activePathsForBackupTest(t, dest)
	restorer := NewRestorer(dest).WithNodeRole(noderole.RoleCosigner).WithActiveNamespace(destActive)
	if _, err := restorer.RestoreKey(ResolveBackupKeysDir(extractDir), selector, kr, []byte("export-passphrase")); err != nil {
		t.Fatalf("RestoreKey() error = %v", err)
	}
	if stored, ok, err := policy.LoadVerifiedCosignerPolicy(destActive, selector, kr); err != nil || !ok || !bytes.Equal(stored.Bytes, doc) {
		t.Fatalf("rebuilt policy = %q, %v, %v", stored.Bytes, ok, err)
	}
}
