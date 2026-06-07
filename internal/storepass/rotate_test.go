// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRotateReencryptsKeysTemplatesAndMetadata(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	keyPath := paths.KeyFilePath(identityID, "ADDR")
	templatePath := paths.KeyTypeTemplate(identityID, "example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKey)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.KeysMigrated != 1 || result.TemplatesMigrated != 1 ||
		result.PolicySidecarsMigrated != 2 || result.NodeRoleSidecarsMigrated != 1 {
		t.Fatalf("Rotate() result = %+v, want 1 key, 1 template, 2 policy sidecars, and 1 node role sidecar", result)
	}

	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	newMasterKey, err := meta.VerifyAndDeriveMasterKey(newPassphrase)
	if err != nil {
		t.Fatalf("new passphrase does not verify rotated metadata: %v", err)
	}
	defer crypto.ZeroBytes(newMasterKey)
	if oldKey, err := meta.VerifyAndDeriveMasterKey(oldPassphrase); err == nil {
		crypto.ZeroBytes(oldKey)
		t.Fatal("old passphrase still verifies rotated metadata")
	}
	assertDecryptsWithMasterKey(t, keyPath, newMasterKey)
	assertDecryptsWithMasterKey(t, templatePath, newMasterKey)
	assertPolicyVerifiesWithMasterKey(t, paths, identityID, newMasterKey)
	assertNodeRoleVerifiesWithMasterKey(t, paths, identityID, newMasterKey, noderole.RoleSigner)
	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(paths.Root(), identityID, oldMasterKey); err == nil {
		t.Fatal("policy sidecar still verifies with old master key after rotation")
	}
	if _, err := policy.LoadVerifiedAttestationConfigWithMasterKey(paths.Root(), identityID, oldMasterKey); err == nil {
		t.Fatal("attestation sidecar still verifies with old master key after rotation")
	}
	if _, err := noderole.LoadAndVerifyWithMasterKey(paths, identityID, oldMasterKey); err == nil {
		t.Fatal("node role sidecar still verifies with old master key after rotation")
	}
}

func TestRotateRejectsWrongCurrentPassphraseBeforeMutation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	keyPath := paths.KeyFilePath(identityID, "ADDR")
	templatePath := paths.KeyTypeTemplate(identityID, "example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKey)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)

	result, err := Rotate(paths, identityID, []byte("wrong-passphrase"), newPassphrase, RotateOptions{})
	if err == nil {
		t.Fatal("Rotate() error = nil, want current passphrase failure")
	}
	if !strings.Contains(err.Error(), "current passphrase verification failed") {
		t.Fatalf("Rotate() error = %v, want current passphrase context", err)
	}
	if result.KeysMigrated != 0 || result.TemplatesMigrated != 0 || result.PolicySidecarsMigrated != 0 {
		t.Fatalf("Rotate() result = %+v, want no migrated files", result)
	}

	assertMetadataAcceptsPassphrase(t, paths, identityID, oldPassphrase)
	assertMetadataRejectsPassphrase(t, paths, identityID, newPassphrase)
	assertDecryptsWithMasterKey(t, keyPath, oldMasterKey)
	assertDecryptsWithMasterKey(t, templatePath, oldMasterKey)
	assertPolicyVerifiesWithMasterKey(t, paths, identityID, oldMasterKey)
	assertNodeRoleVerifiesWithMasterKey(t, paths, identityID, oldMasterKey, noderole.RoleSigner)
	assertNoRotationArtifacts(t, keyPath, templatePath, filepath.Join(paths.KeystoreMetadataDir(identityID), ".keystore"), policy.PolicyIntegritySidecarPath(policy.PolicyPath(paths.Root(), identityID)), policy.PolicyIntegritySidecarPath(policy.AttestationPath(paths.Root(), identityID)), paths.NodeRoleIntegritySidecar(identityID))
}

func TestRotateRollsBackWhenAfterSwapFails(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	keyPath := paths.KeyFilePath(identityID, "ADDR")
	templatePath := paths.KeyTypeTemplate(identityID, "example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKey)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{
		AfterSwap: func() error {
			return errors.New("helper write failed")
		},
	})
	if err == nil {
		t.Fatal("Rotate() error = nil, want after-swap failure")
	}
	if !strings.Contains(err.Error(), "helper write failed") {
		t.Fatalf("Rotate() error = %v, want helper failure context", err)
	}
	if result.KeysMigrated != 1 || result.TemplatesMigrated != 1 ||
		result.PolicySidecarsMigrated != 2 || result.NodeRoleSidecarsMigrated != 1 {
		t.Fatalf("Rotate() result = %+v, want attempted key, template, policy, and node role migration", result)
	}

	assertMetadataAcceptsPassphrase(t, paths, identityID, oldPassphrase)
	assertMetadataRejectsPassphrase(t, paths, identityID, newPassphrase)
	assertDecryptsWithMasterKey(t, keyPath, oldMasterKey)
	assertDecryptsWithMasterKey(t, templatePath, oldMasterKey)
	assertPolicyVerifiesWithMasterKey(t, paths, identityID, oldMasterKey)
	assertNodeRoleVerifiesWithMasterKey(t, paths, identityID, oldMasterKey, noderole.RoleSigner)
	assertNoRotationArtifacts(t, keyPath, templatePath, filepath.Join(paths.KeystoreMetadataDir(identityID), ".keystore"), policy.PolicyIntegritySidecarPath(policy.PolicyPath(paths.Root(), identityID)), policy.PolicyIntegritySidecarPath(policy.AttestationPath(paths.Root(), identityID)), paths.NodeRoleIntegritySidecar(identityID))
}

func TestRotateFailsWhenPolicyBaselineMissing(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err == nil {
		t.Fatal("Rotate() error = nil, want missing policy baseline failure")
	}
	if !strings.Contains(err.Error(), "failed to verify policy.yaml integrity") {
		t.Fatalf("Rotate() error = %v, want policy integrity context", err)
	}
	if result.KeysMigrated != 0 || result.TemplatesMigrated != 0 || result.PolicySidecarsMigrated != 0 {
		t.Fatalf("Rotate() result = %+v, want no migrations", result)
	}
	assertMetadataAcceptsPassphrase(t, paths, identityID, oldPassphrase)
	assertMetadataRejectsPassphrase(t, paths, identityID, newPassphrase)
}

func writeEncryptedForRotateTest(t *testing.T, path string, plaintext []byte, masterKey []byte) {
	t.Helper()
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		t.Fatalf("EncryptWithMasterKey() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writePolicyBaselineForRotateTest(t *testing.T, paths storepaths.Paths, identityID string, masterKey []byte, cfg *policy.StoredConfig) {
	t.Helper()
	if err := policy.SaveStoredConfigWithMasterKey(paths.Root(), identityID, cfg, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredConfigWithMasterKey() error = %v", err)
	}
	if err := policy.SaveStoredAttestationConfigWithMasterKey(paths.Root(), identityID, &policy.StoredConfig{}, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredAttestationConfigWithMasterKey() error = %v", err)
	}
}

func writeNodeRoleBaselineForRotateTest(t *testing.T, paths storepaths.Paths, identityID string, masterKey []byte, role noderole.Role) {
	t.Helper()
	roleBytes, _, err := noderole.SaveInitial(paths, role, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	if err := noderole.SaveIdentitySidecarWithMasterKey(paths, identityID, roleBytes, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveIdentitySidecarWithMasterKey() error = %v", err)
	}
}

func assertPolicyVerifiesWithMasterKey(t *testing.T, paths storepaths.Paths, identityID string, masterKey []byte) {
	t.Helper()
	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(paths.Root(), identityID, masterKey); err != nil {
		t.Fatalf("policy sidecar did not verify: %v", err)
	}
	if _, err := policy.LoadVerifiedAttestationConfigWithMasterKey(paths.Root(), identityID, masterKey); err != nil {
		t.Fatalf("attestation sidecar did not verify: %v", err)
	}
}

func assertNodeRoleVerifiesWithMasterKey(t *testing.T, paths storepaths.Paths, identityID string, masterKey []byte, want noderole.Role) {
	t.Helper()
	doc, err := noderole.LoadAndVerifyWithMasterKey(paths, identityID, masterKey)
	if err != nil {
		t.Fatalf("node role sidecar did not verify: %v", err)
	}
	if doc.Role != want {
		t.Fatalf("node role = %q, want %q", doc.Role, want)
	}
}

func assertDecryptsWithMasterKey(t *testing.T, path string, masterKey []byte) {
	t.Helper()
	encrypted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	plaintext, err := crypto.DecryptWithMasterKey(encrypted, masterKey)
	if err != nil {
		t.Fatalf("DecryptWithMasterKey(%s) error = %v", path, err)
	}
	crypto.ZeroBytes(plaintext)
}

func assertMetadataAcceptsPassphrase(t *testing.T, paths storepaths.Paths, identityID string, passphrase []byte) {
	t.Helper()
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey(%q) error = %v", string(passphrase), err)
	}
	crypto.ZeroBytes(masterKey)
}

func assertMetadataRejectsPassphrase(t *testing.T, paths storepaths.Paths, identityID string, passphrase []byte) {
	t.Helper()
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err == nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("VerifyAndDeriveMasterKey(%q) succeeded, want failure", string(passphrase))
	}
}

func assertNoRotationArtifacts(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		for _, suffix := range []string{".new", ".old"} {
			artifactPath := path + suffix
			if _, err := os.Stat(artifactPath); !os.IsNotExist(err) {
				t.Fatalf("rotation artifact %s stat error = %v, want not exist", artifactPath, err)
			}
		}
	}
}
