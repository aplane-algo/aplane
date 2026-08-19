// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepass

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/falcon"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
	nativefalconsignerreg "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

func TestRotateRejectsPendingTermRotationBeforeScanningTargets(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	kr, err := crypto.CreateKeyringStore(
		paths.KeystoreMetadataDir(),
		oldPassphrase,
	)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	if err := crypto.StartRotation(
		paths.KeystoreMetadataDir(),
		kr,
		oldPassphrase,
		[]crypto.HistoricalGenerationAnchor{},
		func(target *crypto.Keyring, _, _ int64) (crypto.RotationSnapshotReference, error) {
			sealed, err := target.Seal([]byte("cutover"), crypto.RotationSnapshotContext())
			if err != nil {
				return crypto.RotationSnapshotReference{}, err
			}
			return crypto.NewRotationSnapshotReference(sealed)
		},
	); err != nil {
		kr.Zero()
		t.Fatalf("StartRotation() error = %v", err)
	}
	kr.Zero()

	result, err := Rotate(
		paths,
		identityID,
		oldPassphrase,
		[]byte("new-passphrase"),
		RotateOptions{},
	)
	if !errors.Is(err, crypto.ErrRotationPending) {
		t.Fatalf("Rotate() error = %v, want pending rotation failure", err)
	}
	if result != (RotateResult{}) {
		t.Fatalf("Rotate() result = %+v, want no mutation", result)
	}
}

func TestRotateReencryptsKeysTemplatesAndMetadata(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	sentryPath := apkeys.SentryCredentialFilePath(paths, identityID, "WITNESSID")
	templatePath := mustActiveRotate(t, paths, identityID).KeyTypeTemplate("example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKeyRing)
	writeEncryptedForRotateTest(t, sentryPath, []byte(`{"kind":"sentry"}`), oldMasterKeyRing)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKeyRing)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)
	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.KeysMigrated != 2 || result.TemplatesMigrated != 1 || result.PolicySidecarsMigrated != 1 ||
		result.NodeRoleSidecarsMigrated != 1 {
		t.Fatalf(
			"Rotate() result = %+v, want 2 credentials, 1 template, 1 policy sidecar, and 1 node role sidecar",
			result,
		)
	}

	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), newPassphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()
	assertKeyringRejectsPassphrase(t, paths, identityID, oldPassphrase)
	assertDecryptsWithKeyring(t, keyPath, kr)
	assertDecryptsWithKeyring(t, sentryPath, kr)
	assertDecryptsWithKeyring(t, templatePath, kr)
	assertPolicyVerifiesWithKeyring(t, paths, identityID, kr)
	assertNodeRoleVerifiesWithKeyring(t, paths, identityID, kr, noderole.RoleSigner)
	if _, err := policy.LoadVerifiedStoredConfigWithKeyring(paths.Root(), identityID, oldMasterKeyRing); err == nil {
		t.Fatal("policy sidecar still verifies with old master key after rotation")
	}
	if _, err := noderole.LoadAndVerifyWithKeyring(paths, identityID, oldMasterKeyRing); err == nil {
		t.Fatal("node role sidecar still verifies with old master key after rotation")
	}
}

func TestRotatePreservesCanonicalKeyPayloadBytes(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}

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
	writeEncryptedForRotateTest(t, keyPath, keyJSON, oldMasterKeyRing)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.KeysMigrated != 1 {
		t.Fatalf("KeysMigrated = %d, want 1", result.KeysMigrated)
	}

	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), newPassphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()

	rotatedPayload, err := decryptForRotateTest(t, keyPath, kr)
	if err != nil {
		t.Fatalf("decrypt rotated key payload: %v", err)
	}
	defer crypto.ZeroBytes(rotatedPayload)
	if !bytes.Equal(rotatedPayload, keyJSON) {
		t.Fatalf("rotated plaintext payload changed\nbefore:\n%s\nafter:\n%s", keyJSON, rotatedPayload)
	}
}

func TestRotatePreservesNativeFalconAddressAndSigning(t *testing.T) {
	nativefalconsignerreg.RegisterKeyValidator()
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("native-falcon-old-passphrase")
	newPassphrase := []byte("native-falcon-new-passphrase")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}

	entropy := bytes.Repeat([]byte{0x5a}, nativefalcon.RecoveryEntropySize)
	seedInput := append([]byte("PQK"+nativefalcon.Scheme), entropy...)
	workingSeed := sha512.Sum512_256(seedInput)
	crypto.ZeroBytes(seedInput)
	crypto.ZeroBytes(entropy)
	publicKey, privateKey, err := falcon.GenerateKey(workingSeed[:])
	crypto.ZeroBytes(workingSeed[:])
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	defer crypto.ZeroBytes(privateKey[:])
	salt, address, err := nativefalcon.CanonicalAddress(publicKey[:])
	if err != nil {
		t.Fatalf("CanonicalAddress() error = %v", err)
	}
	payload := apkeys.NewNativeFalconPayload(publicKey[:], privateKey[:], salt)
	payload.CreatedAt = time.Unix(1700000000, 0).UTC()
	defer payload.ZeroSecrets()
	keyJSON, err := apkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	defer crypto.ZeroBytes(keyJSON)

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, address.String())
	writeEncryptedForRotateTest(t, keyPath, keyJSON, oldMasterKeyRing)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)
	if _, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{}); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), newPassphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()
	rotatedJSON, err := decryptForRotateTest(t, keyPath, kr)
	if err != nil {
		t.Fatalf("decrypt rotated native Falcon payload: %v", err)
	}
	defer crypto.ZeroBytes(rotatedJSON)
	if !bytes.Equal(rotatedJSON, keyJSON) {
		t.Fatal("native Falcon payload changed during passphrase rotation")
	}

	rotated, err := apkeys.ParsePayload(rotatedJSON)
	if err != nil {
		t.Fatalf("ParsePayload() error = %v", err)
	}
	defer rotated.ZeroSecrets()
	selector, err := rotated.Selector()
	if err != nil || selector != address.String() {
		t.Fatalf("rotated Selector() = %q, %v; want %s", selector, err, address)
	}
	provider := &nativefalconsignerreg.Provider{}
	material, err := provider.LoadKeyMaterial(signing.ProviderKey{
		Type:       rotated.KeyType,
		PrivateKey: rotated.PrivateKey,
	})
	if err != nil {
		t.Fatalf("LoadKeyMaterial() error = %v", err)
	}
	defer provider.ZeroKey(material)
	material.Category = rotated.Category
	material.PQScheme = rotated.PQScheme
	material.PQAddressSalt = rotated.PQAddressSalt
	material.PublicKey = append([]byte(nil), rotated.PublicKey...)
	txn := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: address}}
	signed, err := provider.AuthorizeTransaction(material, txn, address)
	if err != nil {
		t.Fatalf("AuthorizeTransaction() error = %v", err)
	}
	if err := signerops.ValidateTransaction(signed, txn, address); err != nil {
		t.Fatalf("ValidateTransaction() error = %v", err)
	}
}

func TestRotateRejectsWrongCurrentPassphraseBeforeMutation(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	templatePath := mustActiveRotate(t, paths, identityID).KeyTypeTemplate("example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKeyRing)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKeyRing)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)

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
	assertKeyringRejectsPassphrase(t, paths, identityID, newPassphrase)
	assertDecryptsWithKeyring(t, keyPath, oldMasterKeyRing)
	assertDecryptsWithKeyring(t, templatePath, oldMasterKeyRing)
	assertPolicyVerifiesWithKeyring(t, paths, identityID, oldMasterKeyRing)
	assertNodeRoleVerifiesWithKeyring(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)
	assertNoRotationArtifacts(t, keyPath, templatePath, filepath.Join(paths.KeystoreMetadataDir(), ".keystore"), policy.PolicyIntegritySidecarPath(policy.PolicyPath(paths.Root(), identityID)), paths.NodeRoleIntegritySidecar())
}

func TestRotateRejectsTamperedNodeRoleBeforeSwap(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	templatePath := mustActiveRotate(t, paths, identityID).KeyTypeTemplate("example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKeyRing)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKeyRing)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)

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
	if !strings.Contains(err.Error(), "node role integrity check failed") {
		t.Fatalf("Rotate() error = %v, want node role verification context", err)
	}
	if result.NodeRoleSidecarsMigrated != 0 {
		t.Fatalf("Rotate() result = %+v, want no node role sidecar migration", result)
	}

	assertMetadataAcceptsPassphrase(t, paths, identityID, oldPassphrase)
	assertKeyringRejectsPassphrase(t, paths, identityID, newPassphrase)
	assertDecryptsWithKeyring(t, keyPath, oldMasterKeyRing)
	assertDecryptsWithKeyring(t, templatePath, oldMasterKeyRing)
	assertPolicyVerifiesWithKeyring(t, paths, identityID, oldMasterKeyRing)
	if _, err := noderole.LoadAndVerifyWithKeyring(paths, identityID, oldMasterKeyRing); err == nil {
		t.Fatal("tampered node role unexpectedly verifies after failed rotation")
	}
	assertNoRotationArtifacts(t, keyPath, templatePath, filepath.Join(paths.KeystoreMetadataDir(), ".keystore"), policy.PolicyIntegritySidecarPath(policy.PolicyPath(paths.Root(), identityID)), paths.NodeRoleIntegritySidecar())
}

func TestRotateTreatsHelperFailureAsPostCommitWarning(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	templatePath := mustActiveRotate(t, paths, identityID).KeyTypeTemplate("example-v1")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKeyRing)
	writeEncryptedForRotateTest(t, templatePath, []byte("schema_version: 1\n"), oldMasterKeyRing)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)
	helperCalls := 0
	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{
		AfterRootCommit: func() error {
			helperCalls++
			return errors.New("helper write failed")
		},
	})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if !strings.Contains(result.HelperWarning, "helper write failed") {
		t.Fatalf("Rotate() HelperWarning = %q, want helper failure context", result.HelperWarning)
	}
	if helperCalls != 1 {
		t.Fatalf("helper calls = %d, want 1", helperCalls)
	}
	if result.KeysMigrated != 1 || result.TemplatesMigrated != 1 || result.PolicySidecarsMigrated != 1 ||
		result.NodeRoleSidecarsMigrated != 1 {
		t.Fatalf("Rotate() result = %+v, want attempted key, template, policy, and node role migration", result)
	}

	assertMetadataAcceptsPassphrase(t, paths, identityID, newPassphrase)
	assertKeyringRejectsPassphrase(t, paths, identityID, oldPassphrase)
	newKeyring, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), newPassphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore(new passphrase) error = %v", err)
	}
	defer newKeyring.Zero()
	assertDecryptsWithKeyring(t, keyPath, newKeyring)
	assertDecryptsWithKeyring(t, templatePath, newKeyring)
	assertPolicyVerifiesWithKeyring(t, paths, identityID, newKeyring)
	assertNodeRoleVerifiesWithKeyring(t, paths, identityID, newKeyring, noderole.RoleSigner)
	assertNoRotationArtifacts(
		t,
		keyPath,
		templatePath,
		filepath.Join(paths.KeystoreMetadataDir(), ".keystore"),
		policy.PolicyIntegritySidecarPath(policy.PolicyPath(paths.Root(), identityID)),
		paths.NodeRoleIntegritySidecar(),
	)
}

func TestRotateFailsWhenPolicyBaselineMissing(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")
	newPassphrase := []byte("new-passphrase")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)

	result, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{})
	if err == nil {
		t.Fatal("Rotate() error = nil, want missing policy baseline failure")
	}
	if !strings.Contains(err.Error(), "rotation inventory policy") {
		t.Fatalf("Rotate() error = %v, want policy integrity context", err)
	}
	if result.KeysMigrated != 0 || result.TemplatesMigrated != 0 || result.PolicySidecarsMigrated != 0 {
		t.Fatalf("Rotate() result = %+v, want no migrations", result)
	}
	assertMetadataAcceptsPassphrase(t, paths, identityID, oldPassphrase)
	assertKeyringRejectsPassphrase(t, paths, identityID, newPassphrase)
}

// contextForRotateTest is the object identity the store binds into a managed
// file's envelope, chosen the same way production chooses it: from the file's
// canonical location and name.
func contextForRotateTest(t *testing.T, path string) crypto.ObjectContext {
	t.Helper()
	var ctx crypto.ObjectContext
	var err error
	if strings.HasSuffix(path, templatestore.TemplateFileExtension) {
		ctx, err = templatestore.TemplateContextForFile(path)
	} else {
		ctx, err = apkeys.CredentialContextForFile(path)
	}
	if err != nil {
		t.Fatalf("object context for %s: %v", path, err)
	}
	return ctx
}

func writeEncryptedForRotateTest(t *testing.T, path string, plaintext []byte, kr *crypto.Keyring) {
	t.Helper()
	encrypted, err := kr.Seal(plaintext, contextForRotateTest(t, path))
	if err != nil {
		t.Fatalf("encryptWithTermKey() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writePolicyBaselineForRotateTest(t *testing.T, paths storepaths.Paths, identityID string, kr *crypto.Keyring, cfg *policy.StoredConfig) {
	t.Helper()
	if err := policy.SaveStoredConfigWithKeyring(paths.Root(), identityID, cfg, kr, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredConfigWithKeyring() error = %v", err)
	}
}

func writeNodeRoleBaselineForRotateTest(t *testing.T, paths storepaths.Paths, identityID string, kr *crypto.Keyring, role noderole.Role) {
	t.Helper()
	roleBytes, _, err := noderole.SaveInitial(paths, role, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("SaveInitial() error = %v", err)
	}
	if err := noderole.SaveIdentitySidecarWithKeyring(paths, identityID, roleBytes, kr, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveIdentitySidecarWithKeyring() error = %v", err)
	}
}

func assertPolicyVerifiesWithKeyring(t *testing.T, paths storepaths.Paths, identityID string, kr *crypto.Keyring) {
	t.Helper()
	if _, err := policy.LoadVerifiedStoredConfigWithKeyring(paths.Root(), identityID, kr); err != nil {
		t.Fatalf("policy sidecar did not verify: %v", err)
	}
}

func assertNodeRoleVerifiesWithKeyring(t *testing.T, paths storepaths.Paths, identityID string, kr *crypto.Keyring, want noderole.Role) {
	t.Helper()
	doc, err := noderole.LoadAndVerifyWithKeyring(paths, identityID, kr)
	if err != nil {
		t.Fatalf("node role sidecar did not verify: %v", err)
	}
	if doc.Role != want {
		t.Fatalf("node role = %q, want %q", doc.Role, want)
	}
}

func assertDecryptsWithKeyring(t *testing.T, path string, kr *crypto.Keyring) {
	t.Helper()
	plaintext, err := decryptForRotateTest(t, path, kr)
	if err != nil {
		t.Fatalf("decryptWithTermKey(%s) error = %v", path, err)
	}
	crypto.ZeroBytes(plaintext)
}

func decryptForRotateTest(t *testing.T, path string, kr *crypto.Keyring) ([]byte, error) {
	t.Helper()
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return kr.Open(encrypted, contextForRotateTest(t, path))
}

func assertMetadataAcceptsPassphrase(t *testing.T, paths storepaths.Paths, identityID string, passphrase []byte) {
	t.Helper()
	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), passphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore() error = %v", err)
	}
	defer kr.Zero()

}

func assertKeyringRejectsPassphrase(t *testing.T, paths storepaths.Paths, identityID string, passphrase []byte) {
	t.Helper()
	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), passphrase)
	if err == nil {
		kr.Zero()
		t.Fatalf("OpenKeyringStore(%q) succeeded, want failure", string(passphrase))
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

// TestRotatePreservesKeystoreVersionGate proves rotation cannot strip the
// keystore version/layout marker: a downgraded marker would let an older
// binary accept the store and read a layout it does not understand.
func TestRotatePreservesKeystoreVersionGate(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("rotate-generational-old")
	newPassphrase := []byte("rotate-generational-new")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)

	genstoretest.MintFirst(t, paths, identityID)

	if _, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{}); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	// Rotation replaces the root but leaves the format marker alone, so the
	// version gate still recognizes the store and the new passphrase opens it.
	kr, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), newPassphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore(new) error = %v", err)
	}
	kr.Zero()
}

func TestRotateAnchorsPriorGenerationsWithoutPruning(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	passphrase := []byte("rotate-quiescence")

	masterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), passphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	writePolicyBaselineForRotateTest(t, paths, identityID, masterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, masterKeyRing, noderole.RoleSigner)

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
		CreatedAt: time.Unix(1_753_900_001, 0), Integrity: masterKeyRing,
	}); err != nil {
		t.Fatalf("Mint(second): %v", err)
	}

	result, err := Rotate(paths, identityID, passphrase, []byte("new-pass"), RotateOptions{})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if result.PriorGenerations != 1 {
		t.Fatalf("Rotate().PriorGenerations = %d, want 1", result.PriorGenerations)
	}
	rotated, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), []byte("new-pass"))
	if err != nil {
		t.Fatalf("OpenKeyringStore(new-pass) error = %v", err)
	}
	defer rotated.Zero()
	anchors := rotated.HistoricalGenerationAnchors()
	if len(anchors) != 1 || anchors[0].GenerationID != first {
		t.Fatalf("historical anchors = %+v, want %s", anchors, first)
	}
}

func TestRotateDurablyWritesRootAndConsumers(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	identityID := "default"
	oldPassphrase := []byte("old-passphrase")

	oldMasterKeyRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), oldMasterKeyRing)
	writePolicyBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, oldMasterKeyRing, noderole.RoleSigner)

	fileSyncs := map[string]bool{}
	dirSyncs := map[string]bool{}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		switch op {
		case fsutil.OpFileSync:
			fileSyncs[path] = true
		case fsutil.OpDirSync:
			dirSyncs[path] = true
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	if _, err := Rotate(paths, identityID, oldPassphrase, []byte("new-passphrase"), RotateOptions{}); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	if len(fileSyncs) == 0 {
		t.Fatal("rotation performed no durable file writes")
	}
	for _, dir := range []string{filepath.Dir(keyPath), paths.KeystoreMetadataDir()} {
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
func TestRotateReplacesTheTermKey(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	identityID := "default"
	genstoretest.MintFirst(t, paths, identityID)
	oldPassphrase := []byte("term-replacement-old")
	newPassphrase := []byte("term-replacement-new")

	beforeRing, err := crypto.CreateKeyringStore(paths.KeystoreMetadataDir(), oldPassphrase)
	if err != nil {
		t.Fatalf("CreateKeyringStore() error = %v", err)
	}
	defer beforeRing.Zero()

	probeContext := crypto.AccountKeyContext("PROBEADDRESS")
	probe, err := beforeRing.Seal([]byte("probe"), probeContext)
	if err != nil {
		t.Fatalf("Seal(probe) error = %v", err)
	}

	keyPath := apkeys.AccountKeyFilePath(paths, identityID, "ADDR")
	writeEncryptedForRotateTest(t, keyPath, []byte(`{"kind":"key"}`), beforeRing)
	writePolicyBaselineForRotateTest(t, paths, identityID, beforeRing, &policy.StoredConfig{})
	writeNodeRoleBaselineForRotateTest(t, paths, identityID, beforeRing, noderole.RoleSigner)

	if _, err := Rotate(paths, identityID, oldPassphrase, newPassphrase, RotateOptions{}); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	afterRing, err := crypto.OpenKeyringStore(paths.KeystoreMetadataDir(), newPassphrase)
	if err != nil {
		t.Fatalf("OpenKeyringStore(new) error = %v", err)
	}
	defer afterRing.Zero()

	// The probe was never rewritten by rotation, so it is still sealed under
	// the pre-rotation key. If rotation had merely rewrapped that key, the new
	// keyring would open it.
	if plaintext, err := afterRing.Open(probe, probeContext); err == nil {
		crypto.ZeroBytes(plaintext)
		t.Fatal("rotation preserved the term key: a rewrap leaves the old keyring able to read everything written afterwards")
	}
	// The rotated file does open, so the change is a re-encryption under a new
	// key and not merely a discarded one.
	assertDecryptsWithKeyring(t, keyPath, afterRing)
}
