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
		name               string
		prepareSource      func(t *testing.T, sourceDataDir string, apadmin *harness.ApAdminHarness) (string, map[string]string)
		prepareDestination func(t *testing.T, destDataDir string)
		buildSignRequest   func(t *testing.T, address string) signerapi.SignRequest
	}{
		{
			name: "ed25519",
			prepareSource: func(_ *testing.T, _ string, _ *harness.ApAdminHarness) (string, map[string]string) {
				return "ed25519", nil
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
		},
		{
			name: "aplane.falcon1024.v1",
			prepareSource: func(_ *testing.T, _ string, _ *harness.ApAdminHarness) (string, map[string]string) {
				return "aplane.falcon1024.v1", nil
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
		},
		{
			name: "user-loaded HTLC template",
			prepareSource: func(t *testing.T, sourceDataDir string, _ *harness.ApAdminHarness) (string, map[string]string) {
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
		},
		{
			name: "library composed template",
			prepareSource: func(t *testing.T, sourceDataDir string, _ *harness.ApAdminHarness) (string, map[string]string) {
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
		},
		{
			name: "custom generic template",
			prepareSource: func(t *testing.T, sourceDataDir string, apadmin *harness.ApAdminHarness) (string, map[string]string) {
				family := fmt.Sprintf("backup-portability-%d", time.Now().UnixNano())
				keyType := integrationTemplateKeyType(family)
				templatePath := filepath.Join(t.TempDir(), "custom-allowlist.yaml")
				templateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 3
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
  #pragma version 13

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

				mustImportTemplateViaApadmin(t, sourceDataDir, apadmin, templatePath, "custom template")

				return keyType, map[string]string{"recipients": integrationBurnAddress}
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
		},
		{
			name: "custom composed template",
			prepareSource: func(t *testing.T, sourceDataDir string, apadmin *harness.ApAdminHarness) (string, map[string]string) {
				family := fmt.Sprintf("falcon1024-backup-portability-%d", time.Now().UnixNano())
				keyType := integrationTemplateKeyType(family)
				templatePath := filepath.Join(t.TempDir(), "custom-composed-allowlist.yaml")
				templateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 3
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

				mustImportTemplateViaApadmin(t, sourceDataDir, apadmin, templatePath, "custom composed template")

				return keyType, map[string]string{"recipients": integrationBurnAddress}
			},
			buildSignRequest: func(t *testing.T, address string) signerapi.SignRequest {
				return signerapi.SignRequest{
					AuthAddress: address,
					TxnBytesHex: mustUnsignedPaymentTxnHex(t, sp, address, integrationBurnAddress, 0, "backup-portability"),
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
			sourceApadmin := harness.NewApAdminHarness(t, sourceClone.SignerDataDir)
			keyType, generateParams := tc.prepareSource(t, sourceClone.SignerDataDir, sourceApadmin)

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
			if keyType == "ed25519" && harness.IntegrationNetwork() == harness.IntegrationNetworkLocalnet {
				funder, err := harness.NewFundTestAccount(testnet.Client)
				if err != nil {
					t.Fatalf("create LocalNet store acceptance funder: %v", err)
				}
				if err := funder.FundMicroAlgosAndWait(address, 300_000); err != nil {
					t.Fatalf("fund restored-key acceptance account: %v", err)
				}
			}

			storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
			exportPassphrase := storePassphrase
			t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
			archivePath := mustCreateBackupArchive(t, sourceApadmin, address, exportPassphrase)
			mustAssertCredentialOnlyArchiveEntry(t, archivePath, address, exportPassphrase)

			destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
			destApadmin := harness.NewApAdminHarness(t, destClone.SignerDataDir)
			if tc.prepareDestination != nil {
				tc.prepareDestination(t, destClone.SignerDataDir)
			}
			destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
			if destStorePassphrase != exportPassphrase {
				t.Fatalf("test requires identical source/destination store passphrases, got %q vs %q", exportPassphrase, destStorePassphrase)
			}
			t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
			mustRestoreArchive(t, destApadmin, archivePath, exportPassphrase, address)

			destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
			if _, err := os.Stat(apkeys.AccountKeyFilePath(destPaths, address)); err != nil {
				t.Fatalf("restored key file missing for %s: %v", address, err)
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
			keyInventory, err := destClient.GetKeys()
			if err != nil {
				t.Fatalf("list restored destination credentials: %v", err)
			}
			listedKeyType := ""
			for _, key := range keyInventory.Keys {
				if key.Address == address {
					listedKeyType = key.KeyType
					break
				}
			}
			if listedKeyType != keyType {
				t.Fatalf("restored credential key type = %q, want %q", listedKeyType, keyType)
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
			if keyType == "ed25519" && harness.IntegrationNetwork() == harness.IntegrationNetworkLocalnet {
				txids := submitSignedTxnGroup(t, testnet, resp.Signed)
				if len(txids) != 1 {
					t.Fatalf("restored-key submission returned %d txids, want 1", len(txids))
				}
				if _, err := testnet.WaitForConfirmation(txids[0], 10); err != nil {
					t.Fatalf("restored-key transaction did not confirm: %v", err)
				}
			}
		})
	}
}

func TestBackupRestoreRunsThroughSignerIPC(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApadmin := harness.NewApAdminHarness(t, sourceClone.SignerDataDir)

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
	archivePath := mustCreateBackupArchive(t, sourceApadmin, address, storePassphrase)

	if err := sourceSigner.Stop(); err != nil {
		t.Fatalf("failed to stop source signer before starting destination signer: %v", err)
	}

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destSigner := harness.NewSignerHarness(t)
	if err := destSigner.Start(); err != nil {
		t.Fatalf("failed to start destination signer: %v", err)
	}
	t.Cleanup(func() { _ = destSigner.Stop() })

	destApadmin := harness.NewApAdminHarness(t, destClone.SignerDataDir)
	if output, err := runRestoreArchiveWithRunningSigner(t, destApadmin, archivePath, storePassphrase, address); err != nil {
		t.Fatalf("expected restore through running signer to succeed, got %v\noutput:\n%s", err, output)
	}

	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	if _, err := os.Stat(apkeys.AccountKeyFilePath(destPaths, address)); err != nil {
		t.Fatalf("expected restored key file after IPC restore, got stat err=%v", err)
	}
	destToken := readSignerToken(t, destSigner)
	if !waitForKey(t, destSigner.GetURL(), destToken, address, 10*time.Second) {
		t.Fatalf("destination signer did not load IPC-restored key %s", address)
	}
}

func TestSignerManagedBackupRoundTripViaApadminRestore(t *testing.T) {
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
	t.Setenv("APSIGNER_PASSPHRASE", exportPassphrase)
	backupResult, err := sourceApadmin.CreateBackup(exportPassphrase)
	if err != nil {
		t.Fatalf("failed to create signer-managed backup: %v", err)
	}
	// Managed backup responses intentionally expose only the archive basename.
	// Export through authenticated apadmin IPC before moving the archive to a
	// different signer; clients must never depend on the daemon's store path.
	exportDir := t.TempDir()
	if output, err := sourceApadmin.Run("backup", "export", backupResult.ArchivePath, exportDir); err != nil {
		t.Fatalf("failed to export signer-managed backup: %v\noutput:\n%s", err, output)
	}
	archivePath := filepath.Join(exportDir, filepath.Base(backupResult.ArchivePath))
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("exported managed backup archive missing: %v", err)
	}

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	libraryPath := filepath.Join(destPaths.TemplateLibraryDir(), "aplane.htlc.v1.yaml")
	if err := os.Remove(libraryPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove destination aplane.htlc.v1 library template: %v", err)
	}
	installedTemplatePath, pathErr := templatestore.GetTemplateFilePathForPaths(destPaths, "aplane.htlc.v1", templatestore.TemplateTypeGeneric)
	if pathErr != nil {
		t.Fatalf("GetTemplateFilePathForPaths() error = %v", pathErr)
	}
	if err := os.Remove(installedTemplatePath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove destination installed aplane.htlc.v1 template: %v", err)
	}
	destApadmin := harness.NewApAdminHarness(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
	mustRestoreArchive(t, destApadmin, archivePath, exportPassphrase, address)

	destSigner := harness.NewSignerHarness(t)
	if err := destSigner.Start(); err != nil {
		t.Fatalf("failed to start destination signer: %v", err)
	}
	t.Cleanup(func() { _ = destSigner.Stop() })

	t.Cleanup(destApadmin.Cleanup)
	if err := destApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock destination signer: %v", err)
	}

	destToken := readSignerToken(t, destSigner)
	if !waitForKey(t, destSigner.GetURL(), destToken, address, 10*time.Second) {
		t.Fatalf("destination signer did not load restored key %s", address)
	}
}

func TestBackupRestoreStandaloneNoTemplateSucceedsWithoutLocalTemplate(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApadmin := harness.NewApAdminHarness(t, sourceClone.SignerDataDir)
	installHTLCTemplate(t, sourceClone.SignerDataDir)

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

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
	archivePath := mustCreateBackupArchive(t, sourceApadmin, address, storePassphrase)
	mustAssertCredentialOnlyArchiveEntry(t, archivePath, address, storePassphrase)

	destClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	destPaths := utilkeys.NewPaths(destClone.SignerDataDir)
	libraryPath := filepath.Join(destPaths.TemplateLibraryDir(), "aplane.htlc.v1.yaml")
	if err := os.Remove(libraryPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove destination aplane.htlc.v1 library template: %v", err)
	}
	installedTemplatePath, pathErr := templatestore.GetTemplateFilePathForPaths(destPaths, "aplane.htlc.v1", templatestore.TemplateTypeGeneric)
	if pathErr != nil {
		t.Fatalf("GetTemplateFilePathForPaths() error = %v", pathErr)
	}
	if err := os.Remove(installedTemplatePath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("failed to remove destination installed aplane.htlc.v1 template: %v", err)
	}
	destApadmin := harness.NewApAdminHarness(t, destClone.SignerDataDir)
	destStorePassphrase := mustReadPassphrase(t, destClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", destStorePassphrase)
	output, err := runRestoreArchive(t, destApadmin, archivePath, storePassphrase, address)
	if err != nil {
		t.Fatalf("expected standalone key restore without local template or bundled definition, got %v\noutput:\n%s", err, output)
	}
	if _, statErr := os.Stat(apkeys.AccountKeyFilePath(destPaths, address)); statErr != nil {
		t.Fatalf("expected restored key file without local template, got stat err=%v", statErr)
	}
	if templatestore.TemplateExistsForPaths(destPaths, "aplane.htlc.v1", templatestore.TemplateTypeGeneric) {
		t.Fatal("expected standalone restore not to materialize missing aplane.htlc.v1 template")
	}
}

func TestBackupAllArchiveContainsOnlyActiveKeys(t *testing.T) {
	lockOnDisconnect := false
	sourceClone := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	sourceApadmin := harness.NewApAdminHarness(t, sourceClone.SignerDataDir)

	sourceSigner := harness.NewSignerHarness(t)
	if err := sourceSigner.Start(); err != nil {
		t.Fatalf("failed to start source signer: %v", err)
	}
	t.Cleanup(func() { _ = sourceSigner.Stop() })

	t.Cleanup(sourceApadmin.Cleanup)
	if err := sourceApadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock source signer: %v", err)
	}

	activeAddress, err := sourceApadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate active key: %v", err)
	}

	paths := utilkeys.NewPaths(sourceClone.SignerDataDir)
	deletedDir := filepath.Join(paths.ProductDir(), "deleted", "keys")
	if err := os.MkdirAll(deletedDir, 0o755); err != nil {
		t.Fatalf("failed to create deleted keys dir: %v", err)
	}
	deletedAddress, err := sourceApadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}
	deletedKeyPath := apkeys.AccountKeyFilePath(paths, deletedAddress)
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

	storePassphrase := mustReadPassphrase(t, sourceClone.SignerDataDir)
	t.Setenv("APSIGNER_PASSPHRASE", storePassphrase)
	archivePath := mustCreateBackupArchive(t, sourceApadmin, "all", storePassphrase)
	extractDir := mustExtractBackupArchive(t, archivePath)

	if _, err := os.Stat(filepath.Join(extractDir, "apb", activeAddress+".apb")); err != nil {
		t.Fatalf("active key missing from backup all archive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "apb", deletedAddress+".apb")); err == nil {
		t.Fatal("deleted key unexpectedly present in backup all archive")
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

func mustCreateBackupArchive(t *testing.T, apadmin *harness.ApAdminHarness, what, exportPassphrase string) string {
	t.Helper()

	exportDir := t.TempDir()
	createArgs := []string{"backup", "create"}
	if what == "all" {
		createArgs = append(createArgs, "all")
	} else {
		createArgs = append(createArgs, "address", what)
	}
	output, err := apadmin.RunWithInput(exportPassphrase+"\n"+exportPassphrase+"\n", createArgs...)
	if err != nil {
		t.Fatalf("failed to create backup archive for %s: %v\noutput:\n%s", what, err, output)
	}
	managedPath := mustParseManagedBackupPath(t, output)
	archivePath := filepath.Join(exportDir, filepath.Base(managedPath))
	if output, err := apadmin.Run("backup", "export", filepath.Base(managedPath), exportDir); err != nil {
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

func mustRestoreArchive(t *testing.T, apadmin *harness.ApAdminHarness, archivePath, exportPassphrase string, addresses ...string) {
	t.Helper()

	output, err := runRestoreArchive(t, apadmin, archivePath, exportPassphrase, addresses...)
	if err != nil {
		t.Fatalf("failed to restore archive %s: %v\noutput:\n%s", archivePath, err, output)
	}
}

func runRestoreArchive(t *testing.T, apadmin *harness.ApAdminHarness, archivePath, exportPassphrase string, addresses ...string) (string, error) {
	t.Helper()

	var output string
	var err error
	runWithTempSigner(t, func() {
		output, err = runRestoreArchiveWithRunningSigner(t, apadmin, archivePath, exportPassphrase, addresses...)
	})
	return output, err
}

func runRestoreArchiveWithRunningSigner(t *testing.T, apadmin *harness.ApAdminHarness, archivePath, exportPassphrase string, addresses ...string) (string, error) {
	t.Helper()

	if output, err := apadmin.RunWithInput(exportPassphrase+"\n", "backup", "import", archivePath); err != nil {
		return output, err
	}
	args := []string{"restore", "apply", filepath.Base(archivePath)}
	for _, address := range addresses {
		args = append(args, "--address", address)
	}
	return apadmin.RunWithInput(exportPassphrase+"\n", args...)
}

func mustAssertCredentialOnlyArchiveEntry(t *testing.T, archivePath, address, exportPassphrase string) {
	t.Helper()
	extractDir := mustExtractBackupArchive(t, archivePath)
	sealed, err := os.ReadFile(filepath.Join(extractDir, "apb", address+".apb"))
	if err != nil {
		t.Fatalf("read backup entry: %v", err)
	}
	plaintext, err := apcrypto.DecryptStandalone(sealed, []byte(exportPassphrase))
	if err != nil {
		t.Fatalf("decrypt backup entry: %v", err)
	}
	defer apcrypto.ZeroBytes(plaintext)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &fields); err != nil {
		t.Fatalf("parse credential backup entry: %v", err)
	}
	for _, forbidden := range []string{"backup_bundle", "payload_version", "template_yaml", "template_type"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("credential backup entry contains operational field %q", forbidden)
		}
	}
}

func mustExtractBackupArchive(t *testing.T, archivePath string) string {
	t.Helper()

	extractDir := t.TempDir()
	if err := backupbundle.ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("failed to extract backup archive %s: %v", archivePath, err)
	}
	return extractDir
}
