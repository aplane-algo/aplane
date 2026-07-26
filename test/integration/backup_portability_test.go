// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	backupbundle "github.com/aplane-algo/aplane/internal/backup"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

func TestBackupPortabilityFirstMilestone(t *testing.T) {
	lockOnDisconnect := false

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}

	cases := []struct {
		name                   string
		expectedTemplateType   templatestore.TemplateType
		expectBundledTemplate  bool
		prepareSource          func(t *testing.T, sourceDataDir string, apstore *harness.ApStoreHarness) (string, map[string]string)
		prepareDestination     func(t *testing.T, destDataDir string)
		buildSignRequest       func(t *testing.T, address string) signerapi.SignRequest
		assertRestoreArtifacts func(t *testing.T, destPaths utilkeys.Paths, keyType, address string)
	}{
		{
			name:                  "ed25519",
			expectBundledTemplate: false,
			prepareSource: func(_ *testing.T, _ string, _ *harness.ApStoreHarness) (string, map[string]string) {
				return "ed25519", nil
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
			assertRestoreArtifacts: func(t *testing.T, destPaths utilkeys.Paths, keyType, address string) {
				t.Helper()
			},
		},
		{
			name:                  "aplane.falcon1024.v1",
			expectBundledTemplate: false,
			prepareSource: func(_ *testing.T, _ string, _ *harness.ApStoreHarness) (string, map[string]string) {
				return "aplane.falcon1024.v1", nil
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
			assertRestoreArtifacts: func(t *testing.T, destPaths utilkeys.Paths, keyType, address string) {
				t.Helper()
			},
		},
		{
			name:                  "user-loaded HTLC template",
			expectedTemplateType:  templatestore.TemplateTypeGeneric,
			expectBundledTemplate: true,
			prepareSource: func(t *testing.T, sourceDataDir string, _ *harness.ApStoreHarness) (string, map[string]string) {
				installHTLCTemplate(t, sourceDataDir)
				status, err := testnet.Client.Status().Do(context.Background())
				if err != nil {
					t.Fatalf("failed to get algod status: %v", err)
				}
				preimageHash := sha256.Sum256(bytes.Repeat([]byte("p"), 32))
				return "aplane.htlc.v1", map[string]string{
					"hash":           hex.EncodeToString(preimageHash[:]),
					"recipient":      integrationBurnAddress,
					"refund_address": integrationBurnAddress,
					"timeout_round":  fmt.Sprintf("%d", status.LastRound+1_000),
				}
			},
			prepareDestination: func(t *testing.T, destDataDir string) {
				syncTemplateLibraryFile(t, destDataDir, "aplane.htlc.v1.yaml")
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				preimage := bytes.Repeat([]byte("p"), 32)
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
					LsigArgs: map[string]string{
						"preimage": hex.EncodeToString(preimage),
					},
				}
			},
			assertRestoreArtifacts: func(t *testing.T, destPaths utilkeys.Paths, keyType, address string) {
				t.Helper()
				if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeGeneric) {
					t.Fatalf("restored template %s (%s) not found in destination keystore", keyType, templatestore.TemplateTypeGeneric)
				}
			},
		},
		{
			name:                  "library composed template",
			expectedTemplateType:  templatestore.TemplateTypeComposed,
			expectBundledTemplate: true,
			prepareSource: func(t *testing.T, sourceDataDir string, _ *harness.ApStoreHarness) (string, map[string]string) {
				installFalconAllowlistTemplate(t, sourceDataDir)
				return "aplane.falcon1024-allowlist.v1", map[string]string{"recipients": integrationBurnAddress}
			},
			prepareDestination: func(t *testing.T, destDataDir string) {
				syncTemplateLibraryFile(t, destDataDir, "aplane.falcon1024-allowlist.v1.yaml")
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
			assertRestoreArtifacts: func(t *testing.T, destPaths utilkeys.Paths, keyType, address string) {
				t.Helper()
				if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeComposed) {
					t.Fatalf("restored template %s (%s) not found in destination keystore", keyType, templatestore.TemplateTypeComposed)
				}
			},
		},
		{
			name:                  "custom generic template",
			expectedTemplateType:  templatestore.TemplateTypeGeneric,
			expectBundledTemplate: true,
			prepareSource: func(t *testing.T, sourceDataDir string, apstore *harness.ApStoreHarness) (string, map[string]string) {
				family := fmt.Sprintf("backup-portability-%d", time.Now().UnixNano())
				keyType := integrationTemplateKeyType(family)
				templatePath := filepath.Join(t.TempDir(), "custom-allowlist.yaml")
				templateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 2
template_type: generic
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Backup Portability Custom Allowlist"
description: "Custom allowlist template used by backup portability integration tests"

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
    label: "Allowlisted Addresses"
    description: "Comma-separated Algorand addresses that may receive funds from this LogicSig"

teal: |
  #pragma version 10

  txn RekeyTo
  global ZeroAddress
  ==
  assert

  txn TypeEnum
  int pay
  ==
  assert

  {{range @recipients}}
  txn Receiver
  addr {{.}}
  ==
  bnz allow_receiver
  {{end}}
  err

  allow_receiver:
      txn CloseRemainderTo
      global ZeroAddress
      ==
      bnz allow
      {{range @recipients}}
      txn CloseRemainderTo
      addr {{.}}
      ==
      bnz allow
      {{end}}
      err

  allow:
      int 1
      return
`, integrationTemplatePublisher, family)
				if err := os.WriteFile(templatePath, []byte(templateYAML), 0o600); err != nil {
					t.Fatalf("failed to write custom template YAML: %v", err)
				}

				mustImportTemplateViaApstore(t, sourceDataDir, apstore, templatePath, "custom template")

				return keyType, map[string]string{"recipients": integrationBurnAddress}
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
			assertRestoreArtifacts: func(t *testing.T, destPaths utilkeys.Paths, keyType, address string) {
				t.Helper()
				if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeGeneric) {
					t.Fatalf("restored template %s (%s) not found in destination keystore", keyType, templatestore.TemplateTypeGeneric)
				}
			},
		},
		{
			name:                  "custom composed template",
			expectedTemplateType:  templatestore.TemplateTypeComposed,
			expectBundledTemplate: true,
			prepareSource: func(t *testing.T, sourceDataDir string, apstore *harness.ApStoreHarness) (string, map[string]string) {
				family := fmt.Sprintf("falcon1024-backup-portability-%d", time.Now().UnixNano())
				keyType := integrationTemplateKeyType(family)
				templatePath := filepath.Join(t.TempDir(), "custom-composed-allowlist.yaml")
				templateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Backup Portability Custom Falcon Allowlist"
description: "Custom Falcon allowlist template used by backup portability integration tests"

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
    label: "Allowlisted Addresses"
    description: "Comma-separated Algorand addresses that may receive funds from this Falcon LogicSig"

teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert

  txn TypeEnum
  int pay
  ==
  assert

  txn Receiver
  callsub is_allowlisted
  assert

  txn CloseRemainderTo
  global ZeroAddress
  ==
  bnz end_checks
  txn CloseRemainderTo
  callsub is_allowlisted
  assert

  is_allowlisted:
      {{range @recipients}}
      dup
      byte {{.}}
      ==
      bnz allowlisted
      {{end}}
      pop
      int 0
      retsub

  allowlisted:
      pop
      int 1
      retsub

  end_checks:
`, integrationTemplatePublisher, family)
				if err := os.WriteFile(templatePath, []byte(templateYAML), 0o600); err != nil {
					t.Fatalf("failed to write custom composed template YAML: %v", err)
				}

				mustImportTemplateViaApstore(t, sourceDataDir, apstore, templatePath, "custom composed template")

				return keyType, map[string]string{"recipients": integrationBurnAddress}
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
			assertRestoreArtifacts: func(t *testing.T, destPaths utilkeys.Paths, keyType, address string) {
				t.Helper()
				if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeComposed) {
					t.Fatalf("restored template %s (%s) not found in destination keystore", keyType, templatestore.TemplateTypeComposed)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
			sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)
			keyType, generateParams := tc.prepareSource(t, sourceClone.SignerDataDir, sourceApstore)

			sourceSigner := harness.NewSignerHarness(t)
			if err := sourceSigner.Start(); err != nil {
				t.Fatalf("failed to start source signer: %v", err)
			}
			t.Cleanup(func() { _ = sourceSigner.Stop() })

			sourceApSigner := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
			t.Cleanup(sourceApSigner.Cleanup)
			if err := sourceApSigner.UnlockSigner(); err != nil {
				t.Fatalf("failed to unlock source signer: %v", err)
			}

			sourceToken := readSignerToken(t, sourceSigner)
			sourceClient := signerclient.NewSignerClientWithToken(sourceSigner.GetURL(), sourceToken)
			address := mustAdminGenerateKeyNoCleanup(t, sourceClient, sourceSigner, keyType, generateParams)

			storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
			exportPassphrase := storePassphrase
			t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
			archivePath := mustCreateBackupArchive(t, sourceApstore, address, exportPassphrase)
			templateYAML, templateType := mustReadBackupBundleFromArchive(t, archivePath, address, exportPassphrase)
			if tc.expectBundledTemplate {
				if templateType != string(tc.expectedTemplateType) {
					t.Fatalf("backup template_type = %q, want %q", templateType, tc.expectedTemplateType)
				}
				if strings.TrimSpace(templateYAML) == "" {
					t.Fatal("expected backup bundle to include template_yaml")
				}
			} else {
				if templateType != "" {
					t.Fatalf("backup template_type = %q, want empty", templateType)
				}
				if strings.TrimSpace(templateYAML) != "" {
					t.Fatalf("expected no bundled template_yaml, got %q", templateYAML)
				}
			}

			destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
			destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
			if tc.prepareDestination != nil {
				tc.prepareDestination(t, destClone.SignerDataDir)
			}
			destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
			if destStorePassphrase != exportPassphrase {
				t.Fatalf("test requires identical source/destination store passphrases, got %q vs %q", exportPassphrase, destStorePassphrase)
			}
			t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
			mustRestoreArchive(t, destApstore, archivePath, exportPassphrase, address)

			destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
			if _, err := os.Stat(apkeys.AccountKeyFilePath(destPaths, auth.DefaultIdentityID, address)); err != nil {
				t.Fatalf("restored key file missing for %s: %v", address, err)
			}
			if tc.assertRestoreArtifacts != nil {
				tc.assertRestoreArtifacts(t, destPaths, keyType, address)
			}

			if err := sourceSigner.Stop(); err != nil {
				t.Fatalf("failed to stop source signer before starting destination signer: %v", err)
			}

			destSigner := harness.NewSignerHarness(t)
			if err := destSigner.Start(); err != nil {
				t.Fatalf("failed to start destination signer: %v", err)
			}
			t.Cleanup(func() { _ = destSigner.Stop() })

			destApSigner := harness.NewApAdminHarness(t, destSigner.GetWorkDir())
			t.Cleanup(destApSigner.Cleanup)
			if err := destApSigner.UnlockSigner(); err != nil {
				t.Fatalf("failed to unlock destination signer: %v", err)
			}

			destToken := readSignerToken(t, destSigner)
			if !waitForKey(t, destSigner.GetURL(), destToken, address, 10*time.Second) {
				t.Fatalf("destination signer did not load restored key %s", address)
			}

			destClient := signerclient.NewSignerClientWithToken(destSigner.GetURL(), destToken)
			if !waitForKeyType(t, destClient, keyType, 10*time.Second) {
				t.Fatalf("destination signer did not expose restored key type %s", keyType)
			}

			signReq := signerapi.GroupSignRequest{
				Requests: []signerapi.SignRequest{tc.buildSignRequest(t, address)},
			}
			status, body := postSignRequest(t, destSigner.GetURL(), "aplane "+destToken, signReq)
			if status != 200 {
				t.Fatalf("expected destination signing success for %s, got %d: %s", keyType, status, string(body))
			}

			var resp signerapi.GroupSignResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("failed to decode destination sign response: %v", err)
			}
			if resp.Error != "" {
				t.Fatalf("unexpected destination sign error for %s: %s", keyType, resp.Error)
			}
			if len(resp.Signed) < 1 {
				t.Fatalf("expected at least one signed transaction for %s, got %d", keyType, len(resp.Signed))
			}
		})
	}
}

func TestBackupRestoreRunsThroughSignerIPC(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApSigner := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApSigner.Cleanup)
	if err := sourceApSigner.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}
	address, err := sourceApSigner.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate source key: %v", err)
	}

	storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
	archivePath := mustCreateBackupArchive(t, sourceApstore, address, storePassphrase)

	if err := sourceSigner.Stop(); err != nil {
		t.Fatalf("failed to stop source signer before starting destination signer: %v", err)
	}

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destSigner := harness.NewSignerHarness(t)
	if err := destSigner.Start(); err != nil {
		t.Fatalf("failed to start destination signer: %v", err)
	}
	t.Cleanup(func() { _ = destSigner.Stop() })

	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	if output, err := runRestoreArchiveWithRunningSigner(t, destApstore, archivePath, storePassphrase, address); err != nil {
		t.Fatalf("expected restore through running signer to succeed, got %v\noutput:\n%s", err, output)
	}

	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	if _, err := os.Stat(apkeys.AccountKeyFilePath(destPaths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("expected restored key file after IPC restore, got stat err=%v", err)
	}
	destToken := readSignerToken(t, destSigner)
	if !waitForKey(t, destSigner.GetURL(), destToken, address, 10*time.Second) {
		t.Fatalf("destination signer did not load IPC-restored key %s", address)
	}
}

func TestBackupRestoreSkipsConflictingInstalledLibraryBundledTemplate(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)
	installHTLCTemplate(t, sourceClone.SignerDataDir)

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApSigner := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApSigner.Cleanup)
	if err := sourceApSigner.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	sourceToken := readSignerToken(t, sourceSigner)
	sourceClient := signerclient.NewSignerClientWithToken(sourceSigner.GetURL(), sourceToken)
	address := mustAdminGenerateKeyNoCleanup(t, sourceClient, sourceSigner, "aplane.htlc.v1", map[string]string{
		"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"recipient":      integrationBurnAddress,
		"refund_address": integrationBurnAddress,
		"timeout_round":  "999999999",
	})

	storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
	archivePath := mustCreateBackupArchive(t, sourceApstore, address, storePassphrase)
	conflictingTemplatePath, err := filepath.Abs(filepath.Join("..", "..", "library", "templates", "aplane.htlc.v1.yaml"))
	if err != nil {
		t.Fatalf("failed to resolve HTLC template path: %v", err)
	}
	conflictingTemplateYAML, err := os.ReadFile(conflictingTemplatePath)
	if err != nil {
		t.Fatalf("failed to read HTLC template: %v", err)
	}
	conflictingTemplateYAML = bytes.Replace(conflictingTemplateYAML, []byte("    max_items: 16"), []byte("    max_items: 15"), 1)
	if !bytes.Contains(conflictingTemplateYAML, []byte("    max_items: 15")) {
		t.Fatal("failed to create conflicting HTLC template fixture")
	}
	tamperBackupBundleTemplateInArchive(t, archivePath, address, storePassphrase, func(bundle map[string]any) {
		bundle["template_yaml"] = string(conflictingTemplateYAML)
	})

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	installHTLCTemplate(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	if destStorePassphrase != storePassphrase {
		t.Fatalf("test requires identical source/destination store passphrases, got %q vs %q", storePassphrase, destStorePassphrase)
	}
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
	output, err := runRestoreArchive(t, destApstore, archivePath, storePassphrase, address)
	if err != nil {
		t.Fatalf("expected restore to skip conflicting installed library bundled template, got %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "skipped bundled template") ||
		!strings.Contains(output, "backup template conflicts with authoritative local definition") {
		t.Fatalf("expected skipped bundled template warning, got output:\n%s", output)
	}

	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	if _, statErr := os.Stat(apkeys.AccountKeyFilePath(destPaths, auth.DefaultIdentityID, address)); statErr != nil {
		t.Fatalf("expected restored key file despite template conflict, got stat err=%v", statErr)
	}
	if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, "aplane.htlc.v1", templatestore.TemplateTypeGeneric) {
		t.Fatal("expected destination template file to remain after template conflict")
	}
}

func TestBackupRestoreSkipsConflictingExistingKeystoreTemplate(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)

	family := fmt.Sprintf("restore-conflict-%d", time.Now().UnixNano())
	keyType := integrationTemplateKeyType(family)

	sourceTemplatePath := filepath.Join(t.TempDir(), "source-custom-template.yaml")
	sourceTemplateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 2
template_type: generic
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Source Custom Template"
description: "source custom template for restore conflict integration test"

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30

teal: |
  #pragma version 10
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  txn Receiver
  addr %s
  ==
  return
`, integrationTemplatePublisher, family, integrationBurnAddress)
	if err := os.WriteFile(sourceTemplatePath, []byte(sourceTemplateYAML), 0o600); err != nil {
		t.Fatalf("failed to write source template: %v", err)
	}

	sourceStorePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", sourceStorePassphrase)
	mustImportTemplateViaApstore(t, sourceClone.SignerDataDir, sourceApstore, sourceTemplatePath, "source custom template")

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApSigner := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApSigner.Cleanup)
	if err := sourceApSigner.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	sourceToken := readSignerToken(t, sourceSigner)
	sourceClient := signerclient.NewSignerClientWithToken(sourceSigner.GetURL(), sourceToken)
	address := mustAdminGenerateKeyNoCleanup(t, sourceClient, sourceSigner, keyType, map[string]string{"recipients": integrationBurnAddress})

	archivePath := mustCreateBackupArchive(t, sourceApstore, address, sourceStorePassphrase)

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	if destStorePassphrase != sourceStorePassphrase {
		t.Fatalf("test requires identical source/destination store passphrases, got %q vs %q", sourceStorePassphrase, destStorePassphrase)
	}
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)

	destTemplatePath := filepath.Join(t.TempDir(), "dest-custom-template.yaml")
	destTemplateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 2
template_type: generic
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Destination Custom Template"
description: "destination custom template for restore conflict integration test"

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30

teal: |
  #pragma version 10
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  int 0
  return
`, integrationTemplatePublisher, family)
	if err := os.WriteFile(destTemplatePath, []byte(destTemplateYAML), 0o600); err != nil {
		t.Fatalf("failed to write destination template: %v", err)
	}
	mustImportTemplateViaApstore(t, destClone.SignerDataDir, destApstore, destTemplatePath, "destination custom template")

	output, err := runRestoreArchive(t, destApstore, archivePath, destStorePassphrase, address)
	if err != nil {
		t.Fatalf("expected restore to skip conflicting existing destination template, got %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "skipped bundled template") ||
		!strings.Contains(output, "backup template conflicts with existing keystore definition") {
		t.Fatalf("expected skipped bundled template warning, got output:\n%s", output)
	}

	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	if _, statErr := os.Stat(apkeys.AccountKeyFilePath(destPaths, auth.DefaultIdentityID, address)); statErr != nil {
		t.Fatalf("expected restored key file despite destination template conflict, got stat err=%v", statErr)
	}
	if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeGeneric) {
		t.Fatal("expected destination custom template to remain present after restore")
	}
}

func TestBackupRestoreAllowsMatchingExistingKeystoreTemplate(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)

	family := fmt.Sprintf("restore-idempotent-%d", time.Now().UnixNano())
	keyType := integrationTemplateKeyType(family)

	templatePath := filepath.Join(t.TempDir(), "shared-custom-template.yaml")
	templateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 2
template_type: generic
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Shared Custom Template"
description: "shared custom template for restore idempotency integration test"

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30

teal: |
  #pragma version 10
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  txn Receiver
  addr %s
  ==
  return
`, integrationTemplatePublisher, family, integrationBurnAddress)
	if err := os.WriteFile(templatePath, []byte(templateYAML), 0o600); err != nil {
		t.Fatalf("failed to write shared template: %v", err)
	}

	sourceStorePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", sourceStorePassphrase)
	mustImportTemplateViaApstore(t, sourceClone.SignerDataDir, sourceApstore, templatePath, "source custom template")

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApSigner := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApSigner.Cleanup)
	if err := sourceApSigner.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	sourceToken := readSignerToken(t, sourceSigner)
	sourceClient := signerclient.NewSignerClientWithToken(sourceSigner.GetURL(), sourceToken)
	address := mustAdminGenerateKeyNoCleanup(t, sourceClient, sourceSigner, keyType, map[string]string{"recipients": integrationBurnAddress})

	archivePath := mustCreateBackupArchive(t, sourceApstore, address, sourceStorePassphrase)

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	if destStorePassphrase != sourceStorePassphrase {
		t.Fatalf("test requires identical source/destination store passphrases, got %q vs %q", sourceStorePassphrase, destStorePassphrase)
	}
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
	mustImportTemplateViaApstore(t, destClone.SignerDataDir, destApstore, templatePath, "destination custom template")

	mustRestoreArchive(t, destApstore, archivePath, destStorePassphrase, address)

	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	if _, err := os.Stat(apkeys.AccountKeyFilePath(destPaths, auth.DefaultIdentityID, address)); err != nil {
		t.Fatalf("expected restored key file after idempotent restore: %v", err)
	}
	if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeGeneric) {
		t.Fatal("expected destination custom template to remain present after idempotent restore")
	}
}

func TestBackupRestoreSkipsConflictingExistingComposedKeystoreTemplate(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)

	family := fmt.Sprintf("falcon1024-restore-conflict-%d", time.Now().UnixNano())
	keyType := integrationTemplateKeyType(family)

	sourceTemplatePath := filepath.Join(t.TempDir(), "source-custom-composed-template.yaml")
	sourceTemplateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Source Custom Composed Template"
description: "source custom composed template for restore conflict integration test"

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30

teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert

  txn Receiver
  callsub is_allowlisted
  assert

  is_allowlisted:
      {{range @recipients}}
      dup
      byte {{.}}
      ==
      bnz allowlisted
      {{end}}
      pop
      int 0
      retsub

  allowlisted:
      pop
      int 1
      retsub
`, integrationTemplatePublisher, family)
	if err := os.WriteFile(sourceTemplatePath, []byte(sourceTemplateYAML), 0o600); err != nil {
		t.Fatalf("failed to write source composed template: %v", err)
	}

	sourceStorePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", sourceStorePassphrase)
	mustImportTemplateViaApstore(t, sourceClone.SignerDataDir, sourceApstore, sourceTemplatePath, "source custom composed template")

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApSigner := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApSigner.Cleanup)
	if err := sourceApSigner.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	sourceToken := readSignerToken(t, sourceSigner)
	sourceClient := signerclient.NewSignerClientWithToken(sourceSigner.GetURL(), sourceToken)
	address := mustAdminGenerateKeyNoCleanup(t, sourceClient, sourceSigner, keyType, map[string]string{"recipients": integrationBurnAddress})

	archivePath := mustCreateBackupArchive(t, sourceApstore, address, sourceStorePassphrase)

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	if destStorePassphrase != sourceStorePassphrase {
		t.Fatalf("test requires identical source/destination store passphrases, got %q vs %q", sourceStorePassphrase, destStorePassphrase)
	}
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)

	destTemplatePath := filepath.Join(t.TempDir(), "dest-custom-composed-template.yaml")
	destTemplateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Destination Custom Composed Template"
description: "destination custom composed template for restore conflict integration test"

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30

teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert

  int 0
  return
`, integrationTemplatePublisher, family)
	if err := os.WriteFile(destTemplatePath, []byte(destTemplateYAML), 0o600); err != nil {
		t.Fatalf("failed to write destination composed template: %v", err)
	}
	mustImportTemplateViaApstore(t, destClone.SignerDataDir, destApstore, destTemplatePath, "destination custom composed template")

	output, err := runRestoreArchive(t, destApstore, archivePath, destStorePassphrase, address)
	if err != nil {
		t.Fatalf("expected restore to skip conflicting existing destination composed template, got %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "skipped bundled template") ||
		!strings.Contains(output, "backup template conflicts with existing keystore definition") {
		t.Fatalf("expected skipped bundled template warning, got output:\n%s", output)
	}

	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	if _, statErr := os.Stat(apkeys.AccountKeyFilePath(destPaths, auth.DefaultIdentityID, address)); statErr != nil {
		t.Fatalf("expected restored key file despite destination composed template conflict, got stat err=%v", statErr)
	}
	if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, keyType, templatestore.TemplateTypeComposed) {
		t.Fatal("expected destination custom composed template to remain present after restore")
	}
}

func TestSignerManagedBackupRoundTripViaApstoreRestore(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApadmin := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApadmin.Cleanup)
	if err := sourceApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	address, err := sourceApadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate source key: %v", err)
	}

	exportPassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	backupResult, err := sourceApadmin.CreateBackup(exportPassphrase)
	if err != nil {
		t.Fatalf("failed to create signer-managed backup: %v", err)
	}
	if _, err := os.Stat(backupResult.ArchivePath); err != nil {
		t.Fatalf("managed backup archive missing: %v", err)
	}

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	libraryPath := filepath.Join(destPaths.TemplateLibraryDir(), "aplane.htlc.v1.yaml")
	if err := os.Remove(libraryPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove destination aplane.htlc.v1 library template: %v", err)
	}
	installedTemplatePath := templatestore.GetTemplateFilePathForPaths(destPaths, auth.DefaultIdentityID, "aplane.htlc.v1", templatestore.TemplateTypeGeneric)
	if err := os.Remove(installedTemplatePath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove destination installed aplane.htlc.v1 template: %v", err)
	}
	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
	mustRestoreArchive(t, destApstore, backupResult.ArchivePath, exportPassphrase, address)

	destSigner := harness.NewSignerHarness(t)
	if err := destSigner.Start(); err != nil {
		t.Fatalf("failed to start destination signer: %v", err)
	}
	t.Cleanup(func() { _ = destSigner.Stop() })

	destApadmin := harness.NewApAdminHarness(t, destSigner.GetWorkDir())
	t.Cleanup(destApadmin.Cleanup)
	if err := destApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock destination signer: %v", err)
	}

	destToken := readSignerToken(t, destSigner)
	if !waitForKey(t, destSigner.GetURL(), destToken, address, 10*time.Second) {
		t.Fatalf("destination signer did not load restored key %s", address)
	}
}

func TestBackupRestoreLegacyNoTemplateFallsBackToShippedLibrary(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)
	installHTLCTemplate(t, sourceClone.SignerDataDir)

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApadmin := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApadmin.Cleanup)
	if err := sourceApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	status, err := testnet.Client.Status().Do(context.Background())
	if err != nil {
		t.Fatalf("failed to get algod status: %v", err)
	}
	preimageHash := sha256.Sum256(bytes.Repeat([]byte("p"), 32))
	sourceToken := readSignerToken(t, sourceSigner)
	sourceClient := signerclient.NewSignerClientWithToken(sourceSigner.GetURL(), sourceToken)
	address := mustAdminGenerateKeyNoCleanup(t, sourceClient, sourceSigner, "aplane.htlc.v1", map[string]string{
		"hash":           hex.EncodeToString(preimageHash[:]),
		"recipient":      integrationBurnAddress,
		"refund_address": integrationBurnAddress,
		"timeout_round":  fmt.Sprintf("%d", status.LastRound+1_000),
	})

	storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
	archivePath := mustCreateBackupArchive(t, sourceApstore, address, storePassphrase)
	tamperBackupBundleTemplateInArchive(t, archivePath, address, storePassphrase, func(bundle map[string]any) {
		delete(bundle, "template_yaml")
		delete(bundle, "template_type")
	})

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	installHTLCTemplate(t, destClone.SignerDataDir)
	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
	mustRestoreArchive(t, destApstore, archivePath, storePassphrase, address)

	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	if !templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, "aplane.htlc.v1", templatestore.TemplateTypeGeneric) {
		t.Fatal("expected fallback restore to materialize aplane.htlc.v1 template")
	}
}

func TestBackupRestoreStandaloneNoTemplateSucceedsWithoutLocalTemplate(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)
	installHTLCTemplate(t, sourceClone.SignerDataDir)

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApadmin := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApadmin.Cleanup)
	if err := sourceApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	status, err := testnet.Client.Status().Do(context.Background())
	if err != nil {
		t.Fatalf("failed to get algod status: %v", err)
	}
	preimageHash := sha256.Sum256(bytes.Repeat([]byte("p"), 32))
	sourceToken := readSignerToken(t, sourceSigner)
	sourceClient := signerclient.NewSignerClientWithToken(sourceSigner.GetURL(), sourceToken)
	address := mustAdminGenerateKeyNoCleanup(t, sourceClient, sourceSigner, "aplane.htlc.v1", map[string]string{
		"hash":           hex.EncodeToString(preimageHash[:]),
		"recipient":      integrationBurnAddress,
		"refund_address": integrationBurnAddress,
		"timeout_round":  fmt.Sprintf("%d", status.LastRound+1_000),
	})

	storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
	archivePath := mustCreateBackupArchive(t, sourceApstore, address, storePassphrase)
	tamperBackupBundleTemplateInArchive(t, archivePath, address, storePassphrase, func(bundle map[string]any) {
		delete(bundle, "template_yaml")
		delete(bundle, "template_type")
	})

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	libraryPath := filepath.Join(destPaths.TemplateLibraryDir(), "aplane.htlc.v1.yaml")
	if err := os.Remove(libraryPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove destination aplane.htlc.v1 library template: %v", err)
	}
	installedTemplatePath := templatestore.GetTemplateFilePathForPaths(destPaths, auth.DefaultIdentityID, "aplane.htlc.v1", templatestore.TemplateTypeGeneric)
	if err := os.Remove(installedTemplatePath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove destination installed aplane.htlc.v1 template: %v", err)
	}
	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
	output, err := runRestoreArchive(t, destApstore, archivePath, storePassphrase, address)
	if err != nil {
		t.Fatalf("expected standalone key restore without local template or bundled definition, got %v\noutput:\n%s", err, output)
	}
	if _, statErr := os.Stat(apkeys.AccountKeyFilePath(destPaths, auth.DefaultIdentityID, address)); statErr != nil {
		t.Fatalf("expected restored key file without local template, got stat err=%v", statErr)
	}
	if templatestore.TemplateExistsForPaths(destPaths, auth.DefaultIdentityID, "aplane.htlc.v1", templatestore.TemplateTypeGeneric) {
		t.Fatal("expected standalone restore not to materialize missing aplane.htlc.v1 template")
	}
}

func TestBackupRestoreReenablesDisabledInstalledTemplate(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)
	installHTLCTemplate(t, sourceClone.SignerDataDir)

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApadmin := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApadmin.Cleanup)
	if err := sourceApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	sourceToken := readSignerToken(t, sourceSigner)
	sourceClient := signerclient.NewSignerClientWithToken(sourceSigner.GetURL(), sourceToken)
	address := mustAdminGenerateKeyNoCleanup(t, sourceClient, sourceSigner, "aplane.htlc.v1", map[string]string{
		"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"recipient":      integrationBurnAddress,
		"refund_address": integrationBurnAddress,
		"timeout_round":  "999999999",
	})

	storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
	archivePath := mustCreateBackupArchive(t, sourceApstore, address, storePassphrase)

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destApstore := harness.NewApStoreHarness(t, destClone.SignerDataDir)
	installHTLCTemplate(t, destClone.SignerDataDir)
	syncTemplateLibraryFile(t, destClone.SignerDataDir, "aplane.htlc.v1.yaml")
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)

	destSigner := harness.NewSignerHarness(t)
	if err := destSigner.Start(); err != nil {
		t.Fatalf("failed to start destination signer: %v", err)
	}
	destApadmin := harness.NewApAdminHarness(t, destSigner.GetWorkDir())
	if err := destApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock destination signer: %v", err)
	}
	disableResult, err := destApadmin.DeactivateKeyType("aplane.htlc.v1")
	if err != nil {
		t.Fatalf("failed to deactivate aplane.htlc.v1: %v", err)
	}
	if !disableResult.Success {
		t.Fatalf("failed to deactivate aplane.htlc.v1: %s", disableResult.Error)
	}
	t.Cleanup(func() { _ = destSigner.Stop() })

	t.Cleanup(destApadmin.Cleanup)
	if output, err := runRestoreArchiveWithRunningSigner(t, destApstore, archivePath, storePassphrase, address); err != nil {
		t.Fatalf("failed to restore key requiring disabled installed template: %v\noutput:\n%s", err, output)
	}

	destToken := readSignerToken(t, destSigner)
	destClient := signerclient.NewSignerClientWithToken(destSigner.GetURL(), destToken)
	if !waitForKeyType(t, destClient, "aplane.htlc.v1", 10*time.Second) {
		t.Fatal("destination signer did not expose aplane.htlc.v1 after restore-based re-enable")
	}
}

func TestBackupAllArchiveContainsOnlyActiveCurrentIdentityKeys(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApstore := harness.NewApStoreHarness(t, sourceClone.SignerDataDir)

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	sourceApadmin := harness.NewApAdminHarness(t, sourceSigner.GetWorkDir())
	t.Cleanup(sourceApadmin.Cleanup)
	if err := sourceApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	activeAddress, err := sourceApadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate active key: %v", err)
	}

	paths := utilkeys.NewPaths(sourceClone.SignerDataDir)
	activeKeyPath := apkeys.AccountKeyFilePath(paths, auth.DefaultIdentityID, activeAddress)
	activeKeyData, err := os.ReadFile(activeKeyPath)
	if err != nil {
		t.Fatalf("failed to read active key file: %v", err)
	}

	deletedDir := filepath.Join(paths.IdentityDir(auth.DefaultIdentityID), "deleted", "keys")
	if err := os.MkdirAll(deletedDir, 0o755); err != nil {
		t.Fatalf("failed to create deleted keys dir: %v", err)
	}
	deletedAddress, err := sourceApadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}
	deletedKeyPath := apkeys.AccountKeyFilePath(paths, auth.DefaultIdentityID, deletedAddress)
	deletedKeyData, err := os.ReadFile(deletedKeyPath)
	if err != nil {
		t.Fatalf("failed to read second key file: %v", err)
	}
	if err := os.Remove(deletedKeyPath); err != nil {
		t.Fatalf("failed to remove second key from active dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(deletedDir, deletedAddress+".key"), deletedKeyData, 0o600); err != nil {
		t.Fatalf("failed to write deleted key file: %v", err)
	}

	otherIdentity := "other"
	if err := os.MkdirAll(paths.KeysDir(otherIdentity), 0o755); err != nil {
		t.Fatalf("failed to create other identity keys dir: %v", err)
	}
	if err := os.WriteFile(apkeys.AccountKeyFilePath(paths, otherIdentity, deletedAddress), activeKeyData, 0o600); err != nil {
		t.Fatalf("failed to write other-identity key file: %v", err)
	}

	storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
	archivePath := mustCreateBackupArchive(t, sourceApstore, "all", storePassphrase)
	extractDir := mustExtractBackupArchive(t, archivePath)

	if _, err := os.Stat(filepath.Join(extractDir, "apb", activeAddress+".apb")); err != nil {
		t.Fatalf("active key missing from backup all archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", deletedAddress+".apb")); err == nil {
		t.Fatal("deleted or other-identity key unexpectedly present in backup all archive")
	} else if !os.IsNotExist(err) {
		t.Fatalf("unexpected stat error for excluded key: %v", err)
	}
}

func mustAdminGenerateKeyNoCleanup(t *testing.T, signerClient *signerclient.Client, signerd *harness.SignerHarness, keyType string, params map[string]string) string {
	t.Helper()

	resp, err := signerClient.AdminGenerate(keyType, params)
	if err != nil {
		t.Fatalf("failed to generate %s via admin API: %v", keyType, err)
	}
	if resp.Address == "" {
		t.Fatalf("admin generate for %s returned empty address", keyType)
	}
	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, resp.Address, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", resp.Address)
	}
	return resp.Address
}

func mustReadPassphrase(t *testing.T, signerDataDir string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(signerDataDir, "passphrase"))
	if err != nil {
		t.Fatalf("failed to read signer passphrase: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func mustReadBackupBundle(t *testing.T, backupPath, exportPassphrase string) (string, string) {
	t.Helper()

	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("failed to read backup file %s: %v", backupPath, err)
	}

	if apcrypto.IsEncrypted(data) {
		data, err = apcrypto.DecryptStandalone(data, []byte(exportPassphrase))
		if err != nil {
			t.Fatalf("failed to decrypt backup file %s: %v", backupPath, err)
		}
	}

	_, templateYAML, templateType, err := backupbundle.ParseBackup(data)
	if err != nil {
		t.Fatalf("failed to parse backup bundle %s: %v", backupPath, err)
	}

	return string(templateYAML), templateType
}

func tamperBackupBundleTemplate(t *testing.T, backupPath, exportPassphrase string, mutate func(bundle map[string]any)) {
	t.Helper()

	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("failed to read backup file %s: %v", backupPath, err)
	}

	if apcrypto.IsEncrypted(data) {
		data, err = apcrypto.DecryptStandalone(data, []byte(exportPassphrase))
		if err != nil {
			t.Fatalf("failed to decrypt backup file %s: %v", backupPath, err)
		}
	}

	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("failed to unmarshal backup bundle %s: %v", backupPath, err)
	}

	mutate(bundle)

	updated, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("failed to marshal updated backup bundle %s: %v", backupPath, err)
	}

	encrypted, err := apcrypto.EncryptStandalone(updated, []byte(exportPassphrase))
	if err != nil {
		t.Fatalf("failed to re-encrypt backup bundle %s: %v", backupPath, err)
	}

	if err := os.WriteFile(backupPath, encrypted, 0o600); err != nil {
		t.Fatalf("failed to rewrite tampered backup bundle %s: %v", backupPath, err)
	}
}

func mustCreateBackupArchive(t *testing.T, apstore *harness.ApStoreHarness, what, exportPassphrase string) string {
	t.Helper()

	exportDir := t.TempDir()
	createArgs := []string{"backup", "create"}
	if what == "all" {
		createArgs = append(createArgs, "all")
	} else {
		createArgs = append(createArgs, "address", what)
	}
	output, err := apstore.RunWithInput(exportPassphrase+"\n"+exportPassphrase+"\n", createArgs...)
	if err != nil {
		t.Fatalf("failed to create backup archive for %s: %v\noutput:\n%s", what, err, output)
	}
	managedPath := mustParseManagedBackupPath(t, output)
	archivePath := filepath.Join(exportDir, filepath.Base(managedPath))
	if output, err := apstore.Run("backup", "export", filepath.Base(managedPath), exportDir); err != nil {
		t.Fatalf("failed to export backup archive for %s: %v\noutput:\n%s", what, err, output)
	}
	return archivePath
}

func mustParseManagedBackupPath(t *testing.T, output string) string {
	t.Helper()

	const prefix = "managed backup created: "
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, prefix)
		if idx < 0 {
			continue
		}
		path := strings.TrimSpace(line[idx+len(prefix):])
		if path != "" {
			return path
		}
	}
	t.Fatalf("managed backup path missing from output:\n%s", output)
	return ""
}

func mustRestoreArchive(t *testing.T, apstore *harness.ApStoreHarness, archivePath, exportPassphrase string, addresses ...string) {
	t.Helper()

	output, err := runRestoreArchive(t, apstore, archivePath, exportPassphrase, addresses...)
	if err != nil {
		t.Fatalf("failed to restore archive %s: %v\noutput:\n%s", archivePath, err, output)
	}
}

func runRestoreArchive(t *testing.T, apstore *harness.ApStoreHarness, archivePath, exportPassphrase string, addresses ...string) (string, error) {
	t.Helper()

	var output string
	var err error
	runWithTempSigner(t, func() {
		output, err = runRestoreArchiveWithRunningSigner(t, apstore, archivePath, exportPassphrase, addresses...)
	})
	return output, err
}

func runRestoreArchiveWithRunningSigner(t *testing.T, apstore *harness.ApStoreHarness, archivePath, exportPassphrase string, addresses ...string) (string, error) {
	t.Helper()
	t.Setenv("APSIGNER_PASSPHRASE", "")

	if output, err := apstore.RunWithInput(exportPassphrase+"\n", "backup", "import", archivePath); err != nil {
		return output, err
	}
	args := []string{"restore", "apply", filepath.Base(archivePath)}
	for _, address := range addresses {
		args = append(args, "--address", address)
	}
	// The shared test environment auto-approves unmatched signing requests, so
	// activation always requires the destination acknowledgement. Record it on
	// the command line rather than answering an interactive prompt.
	args = append(args, "--acknowledge-unattended-signing")
	return apstore.RunWithInput(exportPassphrase+"\n", args...)
}

func mustExtractBackupArchive(t *testing.T, archivePath string) string {
	t.Helper()

	extractDir := t.TempDir()
	if err := backupbundle.ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("failed to extract backup archive %s: %v", archivePath, err)
	}
	return extractDir
}

func mustReadBackupBundleFromArchive(t *testing.T, archivePath, address, exportPassphrase string) (string, string) {
	t.Helper()
	extractDir := mustExtractBackupArchive(t, archivePath)
	return mustReadBackupBundle(t, filepath.Join(extractDir, "apb", address+".apb"), exportPassphrase)
}

func tamperBackupBundleTemplateInArchive(t *testing.T, archivePath, address, exportPassphrase string, mutate func(bundle map[string]any)) {
	t.Helper()

	extractDir := mustExtractBackupArchive(t, archivePath)
	backupPath := filepath.Join(extractDir, "apb", address+".apb")
	tamperBackupBundleTemplate(t, backupPath, exportPassphrase, mutate)
	if err := os.Remove(archivePath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove original backup archive %s: %v", archivePath, err)
	}
	if err := backupbundle.CreateTarGzArchive(extractDir, archivePath); err != nil {
		t.Fatalf("failed to recreate backup archive %s: %v", archivePath, err)
	}
}

func waitForKeyType(t *testing.T, signerClient *signerclient.Client, keyType string, timeout time.Duration) bool {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if waitForKeyTypeInfo(t, signerClient, keyType, time.Second) != nil {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func waitForKeyTypeInfo(t *testing.T, signerClient *signerclient.Client, keyType string, timeout time.Duration) *signerapi.KeyTypeInfo {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := signerClient.GetKeyTypes()
		if err == nil {
			for i := range resp.KeyTypes {
				if resp.KeyTypes[i].KeyType == keyType {
					info := resp.KeyTypes[i]
					return &info
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}
