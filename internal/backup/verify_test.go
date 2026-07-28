// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	utilkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/noderole"
	ed25519signerreg "github.com/aplane-algo/aplane/internal/signing/ed25519/signerreg"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/internal/witness"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const saltCounterForTest byte = 5

func saltedLogicSigBytecodeForTest() []byte {
	return []byte{0x26, 0x01, 0x01, saltCounterForTest, 0x81, 0x01}
}

func TestDeepVerifyBackupValidStandaloneFile(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	address, keyJSON := testEd25519BackupKeyJSON(t)
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.TotalFiles != 1 || report.ValidFiles != 1 || report.FailedFiles != 0 {
		t.Fatalf("report counts = %+v, want 1 valid file", *report)
	}
	if report.Results[0].KeyType != "ed25519" {
		t.Fatalf("KeyType = %q, want ed25519", report.Results[0].KeyType)
	}
}

func TestDeepVerifyBackupValidComponentKeyFile(t *testing.T) {
	falconkeygen.RegisterWitnessKeygen()
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	publicKey, privateKey, err := signerops.New(nil).GenerateKeypair(bytes.Repeat([]byte{0xcd}, 64))
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}
	componentKey, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	payload := utilkeys.NewWitnessPayload(witness.Falcon1024V1, publicKey, privateKey)
	keyJSON, err := utilkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(component) error = %v", err)
	}
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, componentKey+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.TotalFiles != 1 || report.ValidFiles != 1 || report.FailedFiles != 0 {
		t.Fatalf("report counts = %+v, want 1 valid component file", *report)
	}
	if report.Results[0].KeyType != witness.Falcon1024V1 {
		t.Fatalf("KeyType = %q, want %s", report.Results[0].KeyType, witness.Falcon1024V1)
	}
}

func TestDeepVerifyBackupRejectsPlaintextPayload(t *testing.T) {
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	address, keyJSON := testEd25519BackupKeyJSON(t)
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, address+".apb"), keyJSON, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.FailedFiles != 1 {
		t.Fatalf("FailedFiles = %d, want 1", report.FailedFiles)
	}
	if !strings.Contains(report.Results[0].Error, "backup file must be encrypted") {
		t.Fatalf("result.Error = %q, want encrypted rejection", report.Results[0].Error)
	}
}

func TestDeepVerifyBackupValidGenericLogicSigFile(t *testing.T) {
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	bytecode := saltedLogicSigBytecodeForTest()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address derivation error = %v", err)
	}
	payload := utilkeys.NewGenericLSigPayload("unit-generic-v1", nil, bytecode, saltCounterForTest, "", nil, "")
	keyJSON, err := utilkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(generic) error = %v", err)
	}
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address.String()+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.TotalFiles != 1 || report.ValidFiles != 1 || report.FailedFiles != 0 {
		t.Fatalf("report counts = %+v, want 1 valid file", *report)
	}
	if report.Results[0].KeyType != "unit-generic-v1" {
		t.Fatalf("KeyType = %q, want unit-generic-v1", report.Results[0].KeyType)
	}
}

func TestDeepVerifyBackupValidatesBundledGenericTemplateBytecode(t *testing.T) {
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	compiledBytecode := compiledPushbytesSaltBytecode(0)
	storedBytecode, address := saltedBytecodeForTest(t, compiledBytecode)
	keyJSON := genericLSigKeyJSONForTest(t, address, "test.verify-template.v1", storedBytecode, nil)
	bundleJSON := backupBundleForTest(t, keyJSON, genericTemplateYAMLForTest("verify-template"))
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackupWithOptions(backupRoot, "export-passphrase", DeepVerifyOptions{
		ValidateBundledTemplateBytecode: true,
		AlgodClient:                     compileMockClient(t, compiledBytecode),
	})
	if err != nil {
		t.Fatalf("DeepVerifyBackupWithOptions() error = %v", err)
	}
	if report.TotalFiles != 1 || report.ValidFiles != 1 || report.FailedFiles != 0 {
		t.Fatalf("report counts = %+v, want 1 valid file", *report)
	}
}

func TestDeepVerifyBackupRejectsInvalidKeyTypeInBundle(t *testing.T) {
	const invalidKeyType = "test.bad type.v1"

	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	bytecode := saltedLogicSigBytecodeForTest()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address derivation error = %v", err)
	}
	payload := utilkeys.NewGenericLSigPayload(invalidKeyType, nil, bytecode, saltCounterForTest, "", nil, "")
	keyJSON, err := utilkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(generic) error = %v", err)
	}
	bundleJSON := backupBundleForTest(t, keyJSON, genericTemplateYAMLForTest("bad type"))
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address.String()+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.FailedFiles != 1 {
		t.Fatalf("FailedFiles = %d, want 1", report.FailedFiles)
	}
	if got := report.Results[0].Error; !strings.Contains(got, "invalid key_type") || !strings.Contains(got, invalidKeyType) {
		t.Fatalf("result.Error = %q, want invalid key_type rejection", got)
	}
}

func TestDeepVerifyBackupRejectsBundledGenericTemplateBytecodeMismatch(t *testing.T) {
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	storedCompiledBytecode := compiledPushbytesSaltBytecode(0)
	compiledBytecode := compiledPushbytesSaltBytecode(0)
	compiledBytecode[len(compiledBytecode)-1] = 0x02
	storedBytecode, address := saltedBytecodeForTest(t, storedCompiledBytecode)
	keyJSON := genericLSigKeyJSONForTest(t, address, "test.verify-template.v1", storedBytecode, nil)
	bundleJSON := backupBundleForTest(t, keyJSON, genericTemplateYAMLForTest("verify-template"))
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackupWithOptions(backupRoot, "export-passphrase", DeepVerifyOptions{
		ValidateBundledTemplateBytecode: true,
		AlgodClient:                     compileMockClient(t, compiledBytecode),
	})
	if err != nil {
		t.Fatalf("DeepVerifyBackupWithOptions() error = %v", err)
	}
	if report.FailedFiles != 1 {
		t.Fatalf("FailedFiles = %d, want 1", report.FailedFiles)
	}
	if !strings.Contains(report.Results[0].Error, "does not reproduce key bytecode") {
		t.Fatalf("result.Error = %q, want bytecode mismatch", report.Results[0].Error)
	}
}

func TestDeepVerifyBackupIgnoresAlgodHashForSaltedGenericTemplate(t *testing.T) {
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	compiledBytecode := compiledPushbytesSaltBytecode(0)
	storedBytecode, address := saltedBytecodeForTest(t, compiledBytecode)
	keyJSON := genericLSigKeyJSONForTest(t, address, "test.verify-template-address.v1", storedBytecode, nil)
	bundleJSON := backupBundleForTest(t, keyJSON, genericTemplateYAMLForTest("verify-template-address"))
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackupWithOptions(backupRoot, "export-passphrase", DeepVerifyOptions{
		ValidateBundledTemplateBytecode: true,
		AlgodClient:                     compileMockClientWithHash(t, compiledBytecode, logicSigAddressForBytecode([]byte{0x0a, 0x81, 0x01, 0x44})),
	})
	if err != nil {
		t.Fatalf("DeepVerifyBackupWithOptions() error = %v", err)
	}
	if report.TotalFiles != 1 || report.ValidFiles != 1 || report.FailedFiles != 0 {
		t.Fatalf("report counts = %+v, want 1 valid file", *report)
	}
}

func TestDeepVerifyBackupValidFalconLogicSigBytecodeFile(t *testing.T) {
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	bytecode := saltedLogicSigBytecodeForTest()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address derivation error = %v", err)
	}
	payload := utilkeys.NewDSALSigPayload(
		"falcon1024-unit-v1",
		"falcon1024-unit-v1",
		[]byte{0x01},
		[]byte{0x02},
		nil,
		bytecode,
		saltCounterForTest,
		"",
		nil,
		"",
	)
	keyJSON, err := utilkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(dsa) error = %v", err)
	}
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address.String()+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.TotalFiles != 1 || report.ValidFiles != 1 || report.FailedFiles != 0 {
		t.Fatalf("report counts = %+v, want 1 valid file", *report)
	}
	if report.Results[0].KeyType != "falcon1024-unit-v1" {
		t.Fatalf("KeyType = %q, want falcon1024-unit-v1", report.Results[0].KeyType)
	}
}

func TestDeepVerifyBackupRejectsWrongPassphrase(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	address, keyJSON := testEd25519BackupKeyJSON(t)
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), keyJSON, []byte("correct-export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	// The sealed manifest is the first thing a wrong passphrase hits, so
	// verification fails before any per-payload result exists.
	sealTestArchiveManifest(t, backupRoot)
	if _, err := DeepVerifyBackup(backupRoot, "wrong-export-passphrase"); err == nil {
		t.Fatal("DeepVerifyBackup accepted a wrong passphrase")
	}
}

func TestDeepVerifyBackupRejectsMalformedBackupBundleJSON(t *testing.T) {
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	address, _ := testEd25519BackupKeyJSON(t)
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), []byte(`{"backup_bundle":1,"key":`), []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.FailedFiles != 1 {
		t.Fatalf("FailedFiles = %d, want 1", report.FailedFiles)
	}
	if !strings.Contains(report.Results[0].Error, "failed to parse backup payload") {
		t.Fatalf("result.Error = %q, want backup payload parse failure", report.Results[0].Error)
	}
}

func TestDeepVerifyBackupRejectsMalformedBundledTemplate(t *testing.T) {
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	bytecode := saltedLogicSigBytecodeForTest()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address derivation error = %v", err)
	}
	payload := utilkeys.NewGenericLSigPayload("test.bad-template.v1", nil, bytecode, saltCounterForTest, "", nil, "")
	keyJSON, err := utilkeys.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload(generic) error = %v", err)
	}
	bundleJSON, err := json.Marshal(BackupBundle{
		BackupBundle: 1,
		Key:          json.RawMessage(keyJSON),
		TemplateYAML: "schema_version: 1\ntemplate_type: generic\ntemplate_mode: generated\npublisher: test\nfamily: other\nversion: 1\n",
		TemplateType: "generic",
	})
	if err != nil {
		t.Fatalf("json.Marshal(BackupBundle) error = %v", err)
	}
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address.String()+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.FailedFiles != 1 {
		t.Fatalf("FailedFiles = %d, want 1", report.FailedFiles)
	}
	if !strings.Contains(report.Results[0].Error, "invalid bundled template") {
		t.Fatalf("result.Error = %q, want bundled template failure", report.Results[0].Error)
	}
}

func TestDeepVerifyBackupRejectsAddressMismatch(t *testing.T) {
	ed25519signerreg.RegisterSigner()

	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	address, keyJSON := testEd25519BackupKeyJSON(t)
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	mismatchedAddress, _ := testEd25519BackupKeyJSON(t)
	if mismatchedAddress == address {
		t.Fatal("test setup failed: mismatched address unexpectedly matched")
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, mismatchedAddress+".apb"), keyJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}

	sealTestArchiveManifest(t, backupRoot)
	report, err := DeepVerifyBackup(backupRoot, "export-passphrase")
	if err != nil {
		t.Fatalf("DeepVerifyBackup() error = %v", err)
	}
	if report.FailedFiles != 1 {
		t.Fatalf("FailedFiles = %d, want 1", report.FailedFiles)
	}
	if !strings.Contains(report.Results[0].Error, "address mismatch") {
		t.Fatalf("result.Error = %q, want address mismatch", report.Results[0].Error)
	}
}

func testEd25519BackupKeyJSON(t *testing.T) (string, []byte) {
	t.Helper()
	return keystest.Ed25519KeyJSON(t)
}

func genericLSigKeyJSONForTest(t *testing.T, _, keyType string, bytecode []byte, params map[string]string) []byte {
	t.Helper()
	return keystest.GenericLSigKeyJSON(t, keyType, bytecode, saltCounterForTest, params, "")
}

func backupBundleForTest(t *testing.T, keyJSON []byte, templateYAML []byte) []byte {
	t.Helper()

	bundleJSON, err := json.Marshal(BackupBundle{
		BackupBundle: 1,
		Key:          json.RawMessage(keyJSON),
		TemplateYAML: string(templateYAML),
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if err != nil {
		t.Fatalf("json.Marshal(BackupBundle) error = %v", err)
	}
	return bundleJSON
}

func genericTemplateYAMLForTest(family string) []byte {
	return []byte(`schema_version: 1
derivation_version: 1
template_type: generic
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: Verify Template
description: Backup verification test template
teal: |
  #pragma version 8
  int 1
  return
`)
}

func saltedBytecodeForTest(t *testing.T, compiledBytecode []byte) ([]byte, string) {
	t.Helper()

	salted, err := lsigsalt.FindOffCurve(compiledBytecode, lsigsalt.PushbytesLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	return salted.Bytecode, salted.Address.String()
}

func compiledPushbytesSaltBytecode(counter byte) []byte {
	marker := lsigsalt.PushbytesSaltMarker(counter)
	bytecode := []byte{0x0a, 0x80, byte(len(marker))}
	bytecode = append(bytecode, marker...)
	bytecode = append(bytecode, 0x48, 0x81, 0x01)
	return bytecode
}

func compileMockClient(t *testing.T, bytecode []byte) *algod.Client {
	t.Helper()

	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: bytecode})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	return client
}

func compileMockClientWithHash(t *testing.T, bytecode []byte, hash string) *algod.Client {
	t.Helper()

	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, compileMockTransport{bytecode: bytecode, hash: hash})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	return client
}

type compileMockTransport struct {
	bytecode []byte
	hash     string
}

func (m compileMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Path != "/v2/teal/compile" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"message":"unexpected request"}`))),
			Request:    req,
		}, nil
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		return nil, err
	}
	hash := m.hash
	if hash == "" {
		hash = logicSigAddressForBytecode(m.bytecode)
	}
	body := []byte(`{"result":"` + base64.StdEncoding.EncodeToString(m.bytecode) + `","hash":"` + hash + `"}`)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

func logicSigAddressForBytecode(bytecode []byte) string {
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		return ""
	}
	return address.String()
}

func writeStandaloneBackupFile(path string, plaintext, exportPassphrase []byte) error {
	encrypted, err := apcrypto.EncryptStandalone(plaintext, exportPassphrase)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encrypted, 0o600)
}

// sealTestArchiveManifest seals a manifest over a hand-built archive tree so
// deep verification sees the same authenticated shape a real archive has.
func sealTestArchiveManifest(t *testing.T, root string) {
	t.Helper()
	autoApprove := false
	if err := WriteSealedManifest(
		root,
		noderole.RoleSigner,
		time.Unix(1_700_000_000, 0),
		SourceSettingsSnapshot{UserAutoApprove: &autoApprove},
		[]byte("export-passphrase"),
	); err != nil {
		t.Fatalf("WriteSealedManifest() error = %v", err)
	}
}

// unreachableCompileClient models a TEAL compiler that cannot be reached.
func unreachableCompileClient(t *testing.T) *algod.Client {
	t.Helper()
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, unreachableCompileTransport{})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	return client
}

type unreachableCompileTransport struct{}

func (unreachableCompileTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connect: connection refused")
}

// stageBundledTemplateArchive stages an archive whose key bundles a template,
// returning the archive root and the bytecode the template must reproduce.
func stageBundledTemplateArchive(t *testing.T) (string, []byte) {
	t.Helper()
	backupRoot := t.TempDir()
	keysDir := filepath.Join(backupRoot, "apb")
	compiled := compiledPushbytesSaltBytecode(0)
	storedBytecode, address := saltedBytecodeForTest(t, compiled)
	keyJSON := genericLSigKeyJSONForTest(t, address, "test.verify-template.v1", storedBytecode, nil)
	bundleJSON := backupBundleForTest(t, keyJSON, genericTemplateYAMLForTest("verify-template"))
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := writeStandaloneBackupFile(filepath.Join(keysDir, address+".apb"), bundleJSON, []byte("export-passphrase")); err != nil {
		t.Fatalf("writeStandaloneBackupFile() error = %v", err)
	}
	sealTestArchiveManifest(t, backupRoot)
	return backupRoot, compiled
}

// TestDeepVerifyReportsUnreachableCompilerAsProvenanceUnavailable pins the
// distinction the import gate depends on: a compiler that cannot answer is
// absence of evidence, so the key stays valid and the archive is merely
// flagged. A template that compiles into the wrong bytecode is evidence of a
// real problem and must stay a hard failure — covered by the mismatch test.
func TestDeepVerifyReportsUnreachableCompilerAsProvenanceUnavailable(t *testing.T) {
	backupRoot, _ := stageBundledTemplateArchive(t)

	report, err := DeepVerifyBackupWithOptions(backupRoot, "export-passphrase", DeepVerifyOptions{
		ValidateBundledTemplateBytecode: true,
		AlgodClient:                     unreachableCompileClient(t),
	})
	if err != nil {
		t.Fatalf("DeepVerifyBackupWithOptions() error = %v", err)
	}
	if report.FailedFiles != 0 || report.ValidFiles != 1 {
		t.Fatalf("report = %+v, want the key valid despite an unreachable compiler", *report)
	}
	if report.ProvenanceUnavailableFiles != 1 {
		t.Fatalf("ProvenanceUnavailableFiles = %d, want 1", report.ProvenanceUnavailableFiles)
	}
	if !report.Results[0].TemplateProvenanceUnavailable || report.Results[0].TemplateProvenanceNote == "" {
		t.Fatalf("result = %+v, want a provenance-unavailable note", report.Results[0])
	}
}

// TestDeepVerifyKeepsBytecodeMismatchFatal proves the promptable path cannot
// swallow a genuine mismatch: the key fails and is never reported as merely
// unverifiable.
func TestDeepVerifyKeepsBytecodeMismatchFatal(t *testing.T) {
	backupRoot, compiled := stageBundledTemplateArchive(t)
	wrong := append([]byte(nil), compiled...)
	wrong[len(wrong)-1] ^= 0xff

	report, err := DeepVerifyBackupWithOptions(backupRoot, "export-passphrase", DeepVerifyOptions{
		ValidateBundledTemplateBytecode: true,
		AlgodClient:                     compileMockClient(t, wrong),
	})
	if err != nil {
		t.Fatalf("DeepVerifyBackupWithOptions() error = %v", err)
	}
	if report.FailedFiles != 1 {
		t.Fatalf("report = %+v, want the mismatched key to fail", *report)
	}
	if report.ProvenanceUnavailableFiles != 0 || report.Results[0].TemplateProvenanceUnavailable {
		t.Fatalf("a bytecode mismatch was reported as merely unverifiable: %+v", report.Results[0])
	}
}

// TestDeepVerifyReportsMissingCompilerClientAsUnavailable covers the
// no-client-configured path through the same classification.
func TestDeepVerifyReportsMissingCompilerClientAsUnavailable(t *testing.T) {
	backupRoot, _ := stageBundledTemplateArchive(t)

	report, err := DeepVerifyBackupWithOptions(backupRoot, "export-passphrase", DeepVerifyOptions{
		ValidateBundledTemplateBytecode: true,
	})
	if err != nil {
		t.Fatalf("DeepVerifyBackupWithOptions() error = %v", err)
	}
	if report.FailedFiles != 0 || report.ProvenanceUnavailableFiles != 1 {
		t.Fatalf("report = %+v, want provenance unavailable without a client", *report)
	}
}
