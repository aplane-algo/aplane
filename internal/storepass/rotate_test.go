// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
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

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	sentryPath := apkeys.SentryCredentialFilePath(paths, identityID, "WITNESSID")
	templatePath := paths.KeyTypeTemplate(identityID, "example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKey)
	writeEncryptedForRotateTest(t, sentryPath, []byte(`{"kind":"sentry"}`), oldMasterKey)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)
	recoveredBatch := createRecoveredBatchForRotateTest(t, paths, identityID, oldMasterKey)

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.KeysMigrated != 2 || result.TemplatesMigrated != 1 ||
		result.RecoveredFilesMigrated != 2 || result.PolicySidecarsMigrated != 1 ||
		result.NodeRoleSidecarsMigrated != 1 {
		t.Fatalf(
			"Rotate() result = %+v, want 2 credentials, 1 template, 2 recovered files, 1 policy sidecar, and 1 node role sidecar",
			result,
		)
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
	assertDecryptsWithMasterKey(t, sentryPath, newMasterKey)
	assertDecryptsWithMasterKey(t, templatePath, newMasterKey)
	assertPolicyVerifiesWithMasterKey(t, paths, identityID, newMasterKey)
	assertNodeRoleVerifiesWithMasterKey(t, paths, identityID, newMasterKey, noderole.RoleSigner)
	rotatedBatch, err := recovered.LoadBatch(paths, identityID, recoveredBatch.RestoreID, newMasterKey)
	if err != nil {
		t.Fatalf("LoadBatch(new master key) error = %v", err)
	}
	rotatedEntry, err := recovered.LoadEntry(paths, identityID, recoveredBatch.RestoreID, rotatedBatch.Entries[0], newMasterKey)
	if err != nil {
		t.Fatalf("LoadEntry(new master key) error = %v", err)
	}
	rotatedEntry.ZeroSecrets()
	if _, err := recovered.LoadBatch(paths, identityID, recoveredBatch.RestoreID, oldMasterKey); err == nil {
		t.Fatal("recovered batch still decrypts with old master key after rotation")
	}
	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(paths.Root(), identityID, oldMasterKey); err == nil {
		t.Fatal("policy sidecar still verifies with old master key after rotation")
	}
	if _, err := noderole.LoadAndVerifyWithMasterKey(paths, identityID, oldMasterKey); err == nil {
		t.Fatal("node role sidecar still verifies with old master key after rotation")
	}
}

func createRecoveredBatchForRotateTest(
	t *testing.T,
	paths storepaths.Paths,
	identityID string,
	masterKey []byte,
) *recovered.Batch {
	t.Helper()
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(keyJSON)
	archiveSum := sha256.Sum256([]byte("archive"))
	batch, err := recovered.Create(paths, identityID, recovered.CreateRequest{
		ArchiveName:        "backup.tar.gz",
		ArchiveSHA256:      hex.EncodeToString(archiveSum[:]),
		SourceNodeRole:     string(noderole.RoleSigner),
		SourcePolicyStatus: recovered.SourcePolicyMissing,
		Entries: []recovered.Entry{{
			Selector: address,
			Category: apkeys.CategoryEd25519,
			KeyType:  "ed25519",
			KeyJSON:  keyJSON,
		}},
	}, masterKey)
	if err != nil {
		t.Fatalf("recovered.Create() error = %v", err)
	}
	return batch
}

func TestRotateReconcilesRecoveredRotationArtifacts(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)
	batch := createRecoveredBatchForRotateTest(t, paths, identityID, oldMasterKey)
	metadataPath := paths.RecoveredBatchMetadataPath(identityID, batch.RestoreID)
	entryPath := filepath.Join(
		paths.RecoveredBatchEntriesDir(identityID, batch.RestoreID),
		batch.Entries[0].EntryFile,
	)
	for _, path := range []string{metadataPath, entryPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if err := os.WriteFile(path+".old", data, 0o600); err != nil {
			t.Fatalf("WriteFile(%s.old) error = %v", path, err)
		}
		if err := os.WriteFile(path+".new", []byte("interrupted rotation"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s.new) error = %v", path, err)
		}
	}

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.RecoveredFilesMigrated != 2 {
		t.Fatalf("Rotate().RecoveredFilesMigrated = %d, want 2", result.RecoveredFilesMigrated)
	}
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	newMasterKey, err := meta.VerifyAndDeriveMasterKey(newPassphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey(new passphrase) error = %v", err)
	}
	defer crypto.ZeroBytes(newMasterKey)
	if _, err := recovered.LoadBatch(paths, identityID, batch.RestoreID, newMasterKey); err != nil {
		t.Fatalf("LoadBatch(new master key) error = %v", err)
	}
	assertNoRotationArtifacts(t, metadataPath, entryPath)
}

func TestRotateRejectsRecoveredBatchWithUnresolvedState(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)
	batch := createRecoveredBatchForRotateTest(t, paths, identityID, oldMasterKey)
	if err := os.Mkdir(filepath.Join(paths.RecoveredBatchDir(identityID, batch.RestoreID), "activation"), 0o770); err != nil {
		t.Fatalf("Mkdir(activation) error = %v", err)
	}

	if _, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{}); err == nil ||
		!strings.Contains(err.Error(), "resolve it before passphrase rotation") {
		t.Fatalf("Rotate() error = %v, want unresolved recovered-state rejection", err)
	}
	assertMetadataAcceptsPassphrase(t, paths, identityID, oldPassphrase)
	assertMetadataRejectsPassphrase(t, paths, identityID, newPassphrase)
	if _, err := recovered.LoadBatch(paths, identityID, batch.RestoreID, oldMasterKey); err != nil {
		t.Fatalf("LoadBatch(old master key) error = %v", err)
	}
}

func TestRotatePreservesCanonicalKeyPayloadBytes(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	payload := apkeys.NewEd25519Payload(publicKey, privateKey)
	payload.CreatedAt = time.Unix(1700000000, 0).UTC()
	defer payload.ZeroSecrets()

	keyJSON, err := apkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	defer crypto.ZeroBytes(keyJSON)

	selector, err := payload.Selector()
	if err != nil {
		t.Fatalf("Selector() error = %v", err)
	}
	keyPath := apkeys.AccountKeyFilePath(paths, identityID, selector)
	writeEncryptedForRotateTest(t, keyPath, keyJSON, oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.KeysMigrated != 1 {
		t.Fatalf("KeysMigrated = %d, want 1", result.KeysMigrated)
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

	rotatedPayload, err := decryptForRotateTest(keyPath, newMasterKey)
	if err != nil {
		t.Fatalf("decrypt rotated key payload: %v", err)
	}
	defer crypto.ZeroBytes(rotatedPayload)
	if !bytes.Equal(rotatedPayload, keyJSON) {
		t.Fatalf("rotated plaintext payload changed\nbefore:\n%s\nafter:\n%s", keyJSON, rotatedPayload)
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

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
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
	assertNoRotationArtifacts(t, keyPath, templatePath, filepath.Join(paths.KeystoreMetadataDir(identityID), ".keystore"), policy.PolicyIntegritySidecarPath(policy.PolicyPath(paths.Root(), identityID)), paths.NodeRoleIntegritySidecar(identityID))
}

func TestRotateRejectsTamperedNodeRoleBeforeSwap(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	templatePath := paths.KeyTypeTemplate(identityID, "example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKey)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)

	tamperedDoc, err := noderole.NewDocument(noderole.RoleSentry, time.Unix(1700000001, 0))
	if err != nil {
		t.Fatalf("NewDocument() error = %v", err)
	}
	tamperedBytes, err := noderole.MarshalDocument(tamperedDoc)
	if err != nil {
		t.Fatalf("MarshalDocument() error = %v", err)
	}
	if err := os.WriteFile(paths.NodeRolePath(), tamperedBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(node.yaml) error = %v", err)
	}

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err == nil {
		t.Fatal("Rotate() error = nil, want node role integrity failure")
	}
	if !strings.Contains(err.Error(), "failed to verify node role integrity before passphrase rotation") {
		t.Fatalf("Rotate() error = %v, want node role verification context", err)
	}
	if result.NodeRoleSidecarsMigrated != 0 {
		t.Fatalf("Rotate() result = %+v, want no node role sidecar migration", result)
	}

	assertMetadataAcceptsPassphrase(t, paths, identityID, oldPassphrase)
	assertMetadataRejectsPassphrase(t, paths, identityID, newPassphrase)
	assertDecryptsWithMasterKey(t, keyPath, oldMasterKey)
	assertDecryptsWithMasterKey(t, templatePath, oldMasterKey)
	assertPolicyVerifiesWithMasterKey(t, paths, identityID, oldMasterKey)
	if _, err := noderole.LoadAndVerifyWithMasterKey(paths, identityID, oldMasterKey); err == nil {
		t.Fatal("tampered node role unexpectedly verifies after failed rotation")
	}
	assertNoRotationArtifacts(t, keyPath, templatePath, filepath.Join(paths.KeystoreMetadataDir(identityID), ".keystore"), policy.PolicyIntegritySidecarPath(policy.PolicyPath(paths.Root(), identityID)), paths.NodeRoleIntegritySidecar(identityID))
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

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	templatePath := paths.KeyTypeTemplate(identityID, "example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKey)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)
	recoveredBatch := createRecoveredBatchForRotateTest(t, paths, identityID, oldMasterKey)

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
		result.RecoveredFilesMigrated != 2 || result.PolicySidecarsMigrated != 1 ||
		result.NodeRoleSidecarsMigrated != 1 {
		t.Fatalf("Rotate() result = %+v, want attempted key, template, recovered, policy, and node role migration", result)
	}

	assertMetadataAcceptsPassphrase(t, paths, identityID, oldPassphrase)
	assertMetadataRejectsPassphrase(t, paths, identityID, newPassphrase)
	assertDecryptsWithMasterKey(t, keyPath, oldMasterKey)
	assertDecryptsWithMasterKey(t, templatePath, oldMasterKey)
	assertPolicyVerifiesWithMasterKey(t, paths, identityID, oldMasterKey)
	assertNodeRoleVerifiesWithMasterKey(t, paths, identityID, oldMasterKey, noderole.RoleSigner)
	if _, err := recovered.LoadBatch(paths, identityID, recoveredBatch.RestoreID, oldMasterKey); err != nil {
		t.Fatalf("LoadBatch(old master key after rollback) error = %v", err)
	}
	recoveredMetadataPath := paths.RecoveredBatchMetadataPath(identityID, recoveredBatch.RestoreID)
	recoveredEntryPath := filepath.Join(
		paths.RecoveredBatchEntriesDir(identityID, recoveredBatch.RestoreID),
		recoveredBatch.Entries[0].EntryFile,
	)
	assertNoRotationArtifacts(
		t,
		keyPath,
		templatePath,
		recoveredMetadataPath,
		recoveredEntryPath,
		filepath.Join(paths.KeystoreMetadataDir(identityID), ".keystore"),
		policy.PolicyIntegritySidecarPath(policy.PolicyPath(paths.Root(), identityID)),
		paths.NodeRoleIntegritySidecar(identityID),
	)
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
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)

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
	plaintext, err := decryptForRotateTest(path, masterKey)
	if err != nil {
		t.Fatalf("DecryptWithMasterKey(%s) error = %v", path, err)
	}
	crypto.ZeroBytes(plaintext)
}

func decryptForRotateTest(path string, masterKey []byte) ([]byte, error) {
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptWithMasterKey(encrypted, masterKey)
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
