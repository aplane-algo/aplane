// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeintegration_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/storepaths"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestFreshStoreBackupRestoreAndSign(t *testing.T) {
	const (
		sourcePass = "store-source-passphrase"
		destPass   = "store-destination-passphrase"
		exportPass = "store-export-passphrase"
	)
	source := newFreshStoreEnv(t, sourcePass)
	assertStoreUninitialized(t, source)
	source.initialize()
	source.startSigner(sourcePass)

	generated := mustGenerateEd25519(t, source)
	imported := mustImportEd25519(t, source)
	mustWaitForAddresses(t, source, generated, imported)
	assertCanSign(t, source, generated)
	assertCanSign(t, source, imported)

	archive := mustCreateAndExportBackup(t, source, exportPass)
	if output, err := source.runApstore(exportPass+"\n", nil, "verify", archive); err != nil {
		t.Fatalf("verify exported backup: %v\n%s", err, output)
	}

	destination := newFreshStoreEnv(t, destPass)
	assertStoreUninitialized(t, destination)
	destination.initialize()
	destination.startSigner(destPass)
	mustImportAndApplyBackup(t, destination, archive, exportPass)
	mustWaitForAddresses(t, destination, generated, imported)
	assertCanSign(t, destination, generated)
	assertCanSign(t, destination, imported)

	active, err := genstore.Resolve(storepaths.NewPaths(destination.dataDir), "default")
	if err != nil {
		t.Fatalf("resolve restored destination generation: %v", err)
	}
	manifest, err := genstore.ReadManifest(active)
	if err != nil {
		t.Fatalf("read restored destination manifest: %v", err)
	}
	if manifest.Operation != genstore.OperationCredentialRestore || manifest.ParentID == "" {
		t.Fatalf("restored manifest = operation %q parent %q", manifest.Operation, manifest.ParentID)
	}
}

func TestStorePassphraseRotationPreservesSigningAndPriorGeneration(t *testing.T) {
	const (
		oldPass    = "rotation-old-passphrase"
		newPass    = "rotation-new-passphrase"
		exportPass = "rotation-export-passphrase"
	)
	env := newFreshStoreEnv(t, oldPass)
	env.initialize()
	env.startSigner(oldPass)
	address := mustGenerateEd25519(t, env)
	mustWaitForAddresses(t, env, address)
	archive := mustCreateAndExportBackup(t, env, exportPass)
	if output, err := env.runApadmin("--test", "delete", address); err != nil {
		t.Fatalf("delete rotation fixture credential: %v\n%s", err, output)
	}
	mustImportAndApplyBackup(t, env, archive, exportPass)

	paths := storepaths.NewPaths(env.dataDir)
	before, err := genstore.Resolve(paths, "default")
	if err != nil {
		t.Fatalf("resolve pre-rotation generation: %v", err)
	}
	manifest, err := genstore.ReadManifest(before)
	if err != nil || manifest.ParentID == "" {
		t.Fatalf("rotation fixture lacks retained prior generation: manifest=%+v err=%v", manifest, err)
	}

	input := strings.Join([]string{oldPass, newPass, newPass, "y", ""}, "\n")
	output, err := env.runApadminBatch(input, "changepass")
	if err != nil {
		t.Fatalf("changepass: %v\n%s", err, output)
	}
	if !strings.Contains(output, "passphrase change complete") {
		t.Fatalf("changepass did not report completion:\n%s", output)
	}
	assertPassphraseRejected(t, env, oldPass)
	kr := mustOpenKeyring(t, env, newPass)
	if _, pending := kr.PendingRotation(); pending {
		kr.Zero()
		t.Fatal("completed changepass left a pending rotation")
	}
	anchors := kr.HistoricalGenerationAnchors()
	kr.Zero()
	if len(anchors) == 0 {
		t.Fatal("completed rotation did not retain a historical generation anchor")
	}
	assertNoRotationSnapshot(t, env)

	if err := env.stopSigner(); err != nil {
		t.Fatalf("stop signer after changepass: %v", err)
	}
	env.passphrase = newPass
	env.startSigner(newPass)
	mustWaitForAddresses(t, env, address)
	assertCanSign(t, env, address)
}

// TestReleaseArtifactStoreDrill deliberately avoids test-only process features
// so APLANE_TEST_BIN_DIR can point it at the exact release binaries.
func TestReleaseArtifactStoreDrill(t *testing.T) {
	const (
		sourcePass = "release-artifact-source"
		destPass   = "release-artifact-destination"
		newPass    = "release-artifact-rotated"
		exportPass = "release-artifact-export"
	)
	source := newFreshStoreEnv(t, sourcePass)
	source.initialize()
	source.startSigner(sourcePass)
	address := mustGenerateEd25519(t, source)
	mustWaitForAddresses(t, source, address)
	assertCanSign(t, source, address)
	archive := mustCreateAndExportBackup(t, source, exportPass)

	destination := newFreshStoreEnv(t, destPass)
	destination.initialize()
	destination.startSigner(destPass)
	mustImportAndApplyBackup(t, destination, archive, exportPass)
	mustWaitForAddresses(t, destination, address)
	assertCanSign(t, destination, address)

	input := strings.Join([]string{destPass, newPass, newPass, "y", ""}, "\n")
	output, err := destination.runApadminBatch(input, "changepass")
	if err != nil {
		t.Fatalf("release artifact changepass: %v\n%s", err, output)
	}
	if err := destination.stopSigner(); err != nil {
		t.Fatalf("stop release artifact signer: %v", err)
	}
	destination.passphrase = newPass
	destination.startSigner(newPass)
	mustWaitForAddresses(t, destination, address)
	assertCanSign(t, destination, address)
}

func assertStoreUninitialized(t *testing.T, env *storeEnv) {
	t.Helper()
	paths := storepaths.NewPaths(env.dataDir)
	if crypto.KeyringExistsIn(paths.KeystoreMetadataDir()) {
		t.Fatal("fresh store fixture already contains keyring authority")
	}
	if _, err := os.Lstat(paths.ProductDir()); !os.IsNotExist(err) {
		t.Fatalf("fresh store fixture contains an identity directory: %v", err)
	}
}

func storeClient(t *testing.T, env *storeEnv) *signerclient.Client {
	t.Helper()
	token, err := os.ReadFile(filepath.Join(env.dataDir, "identities", "default", "aplane.token"))
	if err != nil {
		t.Fatalf("read signer token: %v", err)
	}
	return signerclient.NewSignerClientWithToken(
		fmt.Sprintf("http://127.0.0.1:%d", env.port),
		strings.TrimSpace(string(token)),
	)
}

func mustGenerateEd25519(t *testing.T, env *storeEnv) string {
	t.Helper()
	result, err := storeClient(t, env).AdminGenerate("ed25519", nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	if result.Address == "" {
		t.Fatal("generate ed25519 returned an empty address")
	}
	return result.Address
}

func mustImportEd25519(t *testing.T, env *storeEnv) string {
	t.Helper()
	account := algocrypto.GenerateAccount()
	words, err := mnemonic.FromPrivateKey(account.PrivateKey)
	if err != nil {
		t.Fatalf("derive import mnemonic: %v", err)
	}
	args := append([]string{"--test", "import", "ed25519"}, strings.Fields(words)...)
	output, err := env.runApadmin(args...)
	if err != nil {
		t.Fatalf("import ed25519 key: %v\n%s", err, output)
	}
	address := account.Address.String()
	if !strings.Contains(output, address) {
		t.Fatalf("import output omitted address %s", address)
	}
	return address
}

func mustWaitForAddresses(t *testing.T, env *storeEnv, addresses ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err := storeClient(t, env).GetKeys()
		if err == nil && !result.Locked {
			seen := make(map[string]bool, len(result.Keys))
			for _, key := range result.Keys {
				seen[key.Address] = true
			}
			complete := true
			for _, address := range addresses {
				complete = complete && seen[address]
			}
			if complete {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("signer did not publish expected addresses: %v", addresses)
}

func assertCanSign(t *testing.T, env *storeEnv, address string) {
	t.Helper()
	response, err := storeClient(t, env).RequestGroupSign([]signerapi.SignRequest{
		mustOfflineSignRequest(t, address),
	})
	if err != nil {
		t.Fatalf("sign with %s: %v", address, err)
	}
	if len(response.Signed) != 1 {
		t.Fatalf("signed response count = %d, want 1", len(response.Signed))
	}
	raw, err := hex.DecodeString(response.Signed[0])
	if err != nil {
		t.Fatalf("decode signed transaction: %v", err)
	}
	var signed types.SignedTxn
	if err := msgpack.Decode(raw, &signed); err != nil {
		t.Fatalf("parse signed transaction: %v", err)
	}
	decodedAddress, err := types.DecodeAddress(address)
	if err != nil {
		t.Fatalf("decode signing address: %v", err)
	}
	message := append([]byte("TX"), msgpack.Encode(signed.Txn)...)
	if !ed25519.Verify(ed25519.PublicKey(decodedAddress[:]), message, signed.Sig[:]) {
		t.Fatal("signed transaction failed Ed25519 verification")
	}
}

func mustOfflineSignRequest(t *testing.T, address string) signerapi.SignRequest {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(
		address,
		address,
		0,
		[]byte("offline-store-integration"),
		"",
		offlineSuggestedParams(t),
	)
	if err != nil {
		t.Fatalf("build offline signing transaction: %v", err)
	}
	encoded := hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...))
	return signerapi.SignRequest{
		AuthAddress: address,
		TxnSender:   address,
		TxnBytesHex: encoded,
	}
}

func assertSigningBlocked(t *testing.T, env *storeEnv, address string) {
	t.Helper()
	response, err := storeClient(t, env).RequestGroupSign([]signerapi.SignRequest{
		mustOfflineSignRequest(t, address),
	})
	if err == nil {
		t.Fatalf("recovery signer returned signing response: %+v", response)
	}
	if response != nil && len(response.Signed) != 0 {
		t.Fatalf("recovery signer returned signed output: %+v", response.Signed)
	}
}

func assertSignerState(t *testing.T, env *storeEnv, want string) {
	t.Helper()
	status, err := storeClient(t, env).GetStatus()
	if err != nil {
		t.Fatalf("get signer status: %v", err)
	}
	if status.State != want {
		t.Fatalf("signer state = %q, want %q", status.State, want)
	}
}

func offlineSuggestedParams(t *testing.T) types.SuggestedParams {
	t.Helper()
	genesisHash, err := base64.StdEncoding.DecodeString(apconfig.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatalf("decode testnet genesis hash: %v", err)
	}
	return types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisHash:     genesisHash,
		GenesisID:       "testnet-v1.0",
		FirstRoundValid: 100,
		LastRoundValid:  200,
		FlatFee:         true,
	}
}

func mustCreateAndExportBackup(t *testing.T, env *storeEnv, exportPass string) string {
	t.Helper()
	output, err := env.runApadminBatch(exportPass+"\n"+exportPass+"\n", "backup", "create", "all")
	if err != nil {
		t.Fatalf("create managed backup: %v\n%s", err, output)
	}
	const prefix = "managed backup created: "
	managedPath := ""
	for _, line := range strings.Split(output, "\n") {
		if index := strings.Index(line, prefix); index >= 0 {
			managedPath = strings.TrimSpace(line[index+len(prefix):])
			break
		}
	}
	if managedPath == "" {
		t.Fatalf("backup output omitted managed path:\n%s", output)
	}
	exportDir := filepath.Join(env.root, "exported")
	if err := os.MkdirAll(exportDir, 0o700); err != nil {
		t.Fatalf("create backup export directory: %v", err)
	}
	output, err = env.runApadminBatch("", "backup", "export", filepath.Base(managedPath), exportDir)
	if err != nil {
		t.Fatalf("export managed backup: %v\n%s", err, output)
	}
	return filepath.Join(exportDir, filepath.Base(managedPath))
}

func mustImportAndApplyBackup(t *testing.T, env *storeEnv, archive, exportPass string, extraApplyArgs ...string) {
	t.Helper()
	imported := filepath.Join(env.root, "incoming-"+filepath.Base(archive))
	copyFile(t, archive, imported)
	output, err := env.runApadminBatch(exportPass+"\n", "backup", "import", imported)
	if err != nil {
		t.Fatalf("import backup: %v\n%s", err, output)
	}
	args := []string{"restore", "apply", filepath.Base(imported)}
	args = append(args, extraApplyArgs...)
	output, err = env.runApadminBatch(exportPass+"\n", args...)
	if err != nil {
		t.Fatalf("apply credential backup: %v\n%s", err, output)
	}
}

func mustOpenKeyring(t *testing.T, env *storeEnv, passphrase string) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.OpenKeyringStore(
		storepaths.NewPaths(env.dataDir).KeystoreMetadataDir(),
		[]byte(passphrase),
	)
	if err != nil {
		t.Fatalf("open keyring with expected passphrase: %v", err)
	}
	return kr
}

func assertPassphraseRejected(t *testing.T, env *storeEnv, passphrase string) {
	t.Helper()
	kr, err := crypto.OpenKeyringStore(
		storepaths.NewPaths(env.dataDir).KeystoreMetadataDir(),
		[]byte(passphrase),
	)
	if kr != nil {
		kr.Zero()
	}
	if err == nil {
		t.Fatal("retired passphrase still opens the keyring")
	}
}

func assertNoRotationSnapshot(t *testing.T, env *storeEnv) {
	t.Helper()
	path := storepaths.NewPaths(env.dataDir).RotationSnapshotPath()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("settled rotation left snapshot %s: %v", path, err)
	}
}
