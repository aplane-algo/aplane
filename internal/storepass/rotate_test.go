// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRotateReencryptsKeysTemplatesAndMetadata(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
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
	templatePath := mustActiveRotate(t, paths, identityID).KeyTypeTemplate("example-v1")
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
	genstoretest.MintFirst(t, paths, "default")
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

func TestRotatePreservesRecoveredBatchPlaintextWithUnknownFields(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
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

	autoApprove := false
	address, keyJSON := keystest.Ed25519KeyJSON(t)
	defer crypto.ZeroBytes(keyJSON)
	archiveSum := sha256.Sum256([]byte("archive"))
	batch, err := recovered.Create(paths, identityID, recovered.CreateRequest{
		ArchiveName:           "backup.tar.gz",
		ArchiveSHA256:         hex.EncodeToString(archiveSum[:]),
		SourceNodeRole:        string(noderole.RoleSigner),
		SourcePolicyStatus:    recovered.SourcePolicyMissing,
		SourceUserAutoApprove: &autoApprove,
		Entries: []recovered.Entry{{
			Selector: address,
			Category: apkeys.CategoryEd25519,
			KeyType:  "ed25519",
			KeyJSON:  keyJSON,
		}},
	}, oldMasterKey)
	if err != nil {
		t.Fatalf("recovered.Create() error = %v", err)
	}

	batchPath := paths.RecoveredBatchMetadataPath(identityID, batch.RestoreID)
	originalPlaintext, err := decryptForRotateTest(batchPath, oldMasterKey)
	if err != nil {
		t.Fatalf("decrypt recovered batch: %v", err)
	}
	defer crypto.ZeroBytes(originalPlaintext)
	if len(originalPlaintext) == 0 || originalPlaintext[len(originalPlaintext)-1] != '}' {
		t.Fatalf("recovered batch plaintext is not a JSON object: %q", originalPlaintext)
	}
	futureField := []byte(`,"future_source_context":{"keep":"exact"}}`)
	injectedPlaintext := make([]byte, 0, len(originalPlaintext)+len(futureField))
	injectedPlaintext = append(injectedPlaintext, originalPlaintext[:len(originalPlaintext)-1]...)
	injectedPlaintext = append(injectedPlaintext, futureField...)
	defer crypto.ZeroBytes(injectedPlaintext)
	var validJSON map[string]json.RawMessage
	if err := json.Unmarshal(injectedPlaintext, &validJSON); err != nil {
		t.Fatalf("injected recovered batch JSON is invalid: %v", err)
	}
	writeEncryptedForRotateTest(t, batchPath, injectedPlaintext, oldMasterKey)

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.RecoveredFilesMigrated != 2 {
		t.Fatalf("RecoveredFilesMigrated = %d, want 2", result.RecoveredFilesMigrated)
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
	rotatedPlaintext, err := decryptForRotateTest(batchPath, newMasterKey)
	if err != nil {
		t.Fatalf("decrypt rotated recovered batch: %v", err)
	}
	defer crypto.ZeroBytes(rotatedPlaintext)
	if !bytes.Equal(rotatedPlaintext, injectedPlaintext) {
		t.Fatalf(
			"rotation changed recovered batch plaintext\nbefore:\n%s\nafter:\n%s",
			injectedPlaintext,
			rotatedPlaintext,
		)
	}
	loaded, err := recovered.LoadBatch(paths, identityID, batch.RestoreID, newMasterKey)
	if err != nil {
		t.Fatalf("LoadBatch(rotated) error = %v", err)
	}
	if loaded.SourceUserAutoApprove == nil || *loaded.SourceUserAutoApprove {
		t.Fatalf("rotated SourceUserAutoApprove = %v, want false", loaded.SourceUserAutoApprove)
	}
}

func TestRotateRejectsRecoveredBatchWithUnresolvedState(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
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
	genstoretest.MintFirst(t, paths, "default")
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
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	templatePath := mustActiveRotate(t, paths, identityID).KeyTypeTemplate("example-v1")
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
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	templatePath := mustActiveRotate(t, paths, identityID).KeyTypeTemplate("example-v1")
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
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	templatePath := mustActiveRotate(t, paths, identityID).KeyTypeTemplate("example-v1")
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
	genstoretest.MintFirst(t, paths, "default")
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

// TestRotatePreservesGenerationalLayoutGate proves rotation cannot strip the
// keystore version/layout marker: a downgraded record would let
// pre-generation binaries accept the store and read its retired flat paths.
func TestRotatePreservesGenerationalLayoutGate(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("rotate-generational-old")
	newPassphrase := []byte("rotate-generational-new")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)

	genstoretest.MintFirst(t, paths, identityID)

	if _, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{}); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	if !meta.IsGenerationalLayout() {
		t.Fatalf("rotation stripped the generational layout gate: version %d layout %q", meta.Version, meta.Layout)
	}
	// The new passphrase verifies against the preserved-version metadata.
	newMasterKey, err := meta.VerifyAndDeriveMasterKey(newPassphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey(new) error = %v", err)
	}
	crypto.ZeroBytes(newMasterKey)
}

// TestRotateRefusedUntilPriorGenerationsPruned proves the documented
// quiescence workflow is completable with supported tooling.
func TestRotateRefusedUntilPriorGenerationsPruned(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	passphrase := []byte("rotate-quiescence")

	_, masterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), passphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(masterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, masterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, masterKey, noderole.RoleSigner)

	first := "gen-1753900000-0badc0de"
	second := "gen-1753900001-1badc0de"
	if _, err := genstore.Mint(paths, identityID, genstore.MintRequest{
		GenerationID: first, FirstGeneration: true, Operation: "test-init", OperationID: "op-1",
		CreatedAt: time.Unix(1_753_900_000, 0),
	}); err != nil {
		t.Fatalf("Mint(first): %v", err)
	}
	if _, err := genstore.Mint(paths, identityID, genstore.MintRequest{
		GenerationID: second, Parent: first, Operation: "test-activation", OperationID: "op-2",
		CreatedAt: time.Unix(1_753_900_001, 0),
	}); err != nil {
		t.Fatalf("Mint(second): %v", err)
	}

	// A sealed prior blocks rotation...
	if _, err := Rotate(paths, identityID, passphrase, []byte("new-pass"), RotateOptions{}); err == nil ||
		!strings.Contains(err.Error(), "quiescence") {
		t.Fatalf("Rotate() error = %v, want quiescence refusal", err)
	}
	// ...and the supported prune restores rotatability.
	if _, err := genstore.CollectGarbage(paths, identityID, nil, false); err != nil {
		t.Fatalf("CollectGarbage() error = %v", err)
	}
	if _, err := Rotate(paths, identityID, passphrase, []byte("new-pass"), RotateOptions{}); err != nil {
		t.Fatalf("Rotate(after prune) error = %v", err)
	}
}

func TestRotateSyncsNewFilesAndSwapDirectories(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")

	_, oldMasterKey, err := crypto.CreateKeystoreMetadata(paths.KeystoreMetadataDir(identityID), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata() error = %v", err)
	}
	defer crypto.ZeroBytes(oldMasterKey)
	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKey)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKey, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKey, noderole.RoleSigner)

	newFileSyncs := map[string]bool{}
	dirSyncs := map[string]bool{}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		switch op {
		case fsutil.OpFileSync:
			if strings.HasSuffix(path, ".new") {
				newFileSyncs[filepath.Base(path)] = true
			}
		case fsutil.OpDirSync:
			dirSyncs[path] = true
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	if _, err := Rotate(paths, identityID, oldPassphrase, []byte("new-passphrase"), RotateOptions{}); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	// Every staged .new file was fsynced before the swap could publish it.
	for _, want := range []string{"ADDR.key.new", ".keystore.new"} {
		if !newFileSyncs[want] {
			t.Fatalf("no file sync observed for %s (synced: %v)", want, newFileSyncs)
		}
	}
	// The swap's renames were made durable in each affected directory.
	for _, dir := range []string{filepath.Dir(keyPath), paths.KeystoreMetadataDir(identityID)} {
		if !dirSyncs[dir] {
			t.Fatalf("no directory sync observed for %s (synced: %v)", dir, dirSyncs)
		}
	}
}

func mustActiveRotate(t *testing.T, paths storepaths.Paths, identityID string) storepaths.ActivePaths {
	t.Helper()
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active
}

// TestRotateReconcilesMidSwapCrashBeforeKeystoreSwap models a crash in the
// middle of phase 2 before the keystore itself swapped: the master key is
// still the old one, one file already swapped (canonical unreadable, .old
// holds the pre-rotation bytes) while another has not (canonical intact,
// .new is the half-installed sibling). The next rotation under the old
// passphrase must restore the swapped file from .old, drop the stale .new,
// and complete.
func TestRotateReconcilesMidSwapCrashBeforeKeystoreSwap(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	finalPassphrase := []byte("final-passphrase")

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

	// Metadata: already swapped. The canonical bytes are the half-installed
	// new-key ciphertext (unreadable under the old master key); .old holds
	// the pre-rotation bytes.
	if err := os.Rename(metadataPath, metadataPath+".old"); err != nil {
		t.Fatalf("Rename(metadata -> .old) error = %v", err)
	}
	if err := os.WriteFile(metadataPath, []byte("half-installed new-key ciphertext"), 0o600); err != nil {
		t.Fatalf("WriteFile(metadata canonical) error = %v", err)
	}
	// Entry: not yet swapped. Canonical intact, .new is the sibling the
	// crash stranded.
	if err := os.WriteFile(entryPath+".new", []byte("stranded new-key ciphertext"), 0o600); err != nil {
		t.Fatalf("WriteFile(entry .new) error = %v", err)
	}

	result, err := Rotate(paths, identityID, oldPassphrase, finalPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.RecoveredFilesMigrated != 2 {
		t.Fatalf("Rotate().RecoveredFilesMigrated = %d, want 2", result.RecoveredFilesMigrated)
	}
	assertRotatedBatchLoads(t, paths, identityID, batch.RestoreID, finalPassphrase)
	assertNoRotationArtifacts(t, metadataPath, entryPath)
}

// TestRotateReconcilesMidSwapCrashAfterKeystoreSwap models a crash after the
// keystore swapped but before every file did: the store's master key is the
// NEW one, one file already carries new-key ciphertext (.old still present)
// while another still carries old-key ciphertext with its .new sibling
// waiting. The next rotation — necessarily under the new passphrase — must
// install the .new sibling, drop the stale .old, and complete.
func TestRotateReconcilesMidSwapCrashAfterKeystoreSwap(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")
	finalPassphrase := []byte("final-passphrase")

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

	// Capture the old-key bytes, then rotate for real to obtain genuine
	// new-key ciphertext for both files.
	oldMetadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("ReadFile(metadata, old key) error = %v", err)
	}
	oldEntryBytes, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatalf("ReadFile(entry, old key) error = %v", err)
	}
	if _, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{}); err != nil {
		t.Fatalf("Rotate(old -> new) error = %v", err)
	}
	newMetadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("ReadFile(metadata, new key) error = %v", err)
	}

	// Metadata: not yet swapped at crash time. Canonical still carries the
	// old-key bytes; .new holds the valid new-key ciphertext.
	if err := os.WriteFile(metadataPath+".new", newMetadataBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(metadata .new) error = %v", err)
	}
	if err := os.WriteFile(metadataPath, oldMetadataBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(metadata canonical) error = %v", err)
	}
	// Entry: already swapped. Canonical is the new-key ciphertext from the
	// real rotation; .old is the stale pre-rotation sibling.
	if err := os.WriteFile(entryPath+".old", oldEntryBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(entry .old) error = %v", err)
	}

	result, err := Rotate(paths, identityID, newPassphrase, finalPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate(new -> final) error = %v", err)
	}
	if result.RecoveredFilesMigrated != 2 {
		t.Fatalf("Rotate().RecoveredFilesMigrated = %d, want 2", result.RecoveredFilesMigrated)
	}
	assertRotatedBatchLoads(t, paths, identityID, batch.RestoreID, finalPassphrase)
	assertNoRotationArtifacts(t, metadataPath, entryPath)
}

// assertRotatedBatchLoads proves the recovered batch decrypts under the
// master key derived from the given passphrase after rotation.
func assertRotatedBatchLoads(t *testing.T, paths storepaths.Paths, identityID, restoreID string, passphrase []byte) {
	t.Helper()
	meta, err := crypto.LoadKeystoreMetadata(paths.KeystoreMetadataDir(identityID))
	if err != nil {
		t.Fatalf("LoadKeystoreMetadata() error = %v", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		t.Fatalf("VerifyAndDeriveMasterKey() error = %v", err)
	}
	defer crypto.ZeroBytes(masterKey)
	if _, err := recovered.LoadBatch(paths, identityID, restoreID, masterKey); err != nil {
		t.Fatalf("LoadBatch(rotated master key) error = %v", err)
	}
}
