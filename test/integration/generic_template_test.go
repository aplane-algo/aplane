// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestGenericAllowlistTemplateAllowsSendAndCloseToFundingAccount(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed generic LSig test")
	}

	lockOnDisconnect := false
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	family := fmt.Sprintf("integration-allowlist-%d", time.Now().UnixNano())
	keyType := integrationTemplateKeyType(family)
	templatePath := writeGenericAllowlistTemplate(t, family)

	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, env.SignerDataDir))
	apstore := harness.NewApStoreHarness(t, env.SignerDataDir)
	mustImportTemplateViaApstore(t, env.SignerDataDir, apstore, templatePath, "generic allowlist")

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy token: %v", err)
	}

	lsigAddr := generateGenericLSigWithShell(t, apshell, keyType, funder.GetAddress())
	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, lsigAddr, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", lsigAddr)
	}

	if err := funder.FundMicroAlgosAndWait(lsigAddr, 500_000); err != nil {
		t.Fatalf("failed to fund generic LSig account: %v", err)
	}

	assertGenericAllowlistRekeyRejected(t, apshell, testnet, lsigAddr, funder.GetAddress())

	sendTxID, err := apshell.SendTransaction(lsigAddr, funder.GetAddress(), 0.05)
	if err != nil {
		t.Fatalf("failed to send from generic allowlist LSig: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(sendTxID, 10); err != nil {
		t.Fatalf("generic allowlist send transaction failed to confirm: %v", err)
	}

	closeTxID, err := apshell.CloseAccount(lsigAddr, funder.GetAddress())
	if err != nil {
		t.Fatalf("failed to close generic allowlist LSig: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(closeTxID, 10); err != nil {
		t.Fatalf("generic allowlist close transaction failed to confirm: %v", err)
	}
}

func TestGenericTemplateLifecycleRejectsDisableAndRemoveWhileKeyExists(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed generic LSig lifecycle test")
	}

	lockOnDisconnect := false
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	family := fmt.Sprintf("integration-lifecycle-allowlist-%d", time.Now().UnixNano())
	keyType := integrationTemplateKeyType(family)
	templatePath := writeGenericFundingClosebackTemplate(t, family, funder.GetAddress())

	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, env.SignerDataDir))
	apstore := harness.NewApStoreHarness(t, env.SignerDataDir)
	mustImportTemplateViaApstore(t, env.SignerDataDir, apstore, templatePath, "lifecycle")

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	disableResult, err := apadmin.DeactivateKeyType(keyType)
	if err != nil {
		t.Fatalf("failed to send initial deactivate IPC message: %v", err)
	}
	if !disableResult.Success || !disableResult.Removed {
		t.Fatalf("initial deactivate result = %+v, want success with state change", disableResult)
	}

	if err := apadmin.ActivateKeyType(keyType); err != nil {
		t.Fatalf("failed to re-enable template key type over IPC: %v", err)
	}

	token := readSignerToken(t, signerd)
	signerClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	resp, err := signerClient.AdminGenerate(keyType, nil)
	if err != nil {
		t.Fatalf("failed to generate lifecycle generic LSig: %v", err)
	}
	lsigAddr := resp.Address
	if lsigAddr == "" {
		t.Fatal("admin generate returned empty lifecycle LSig address")
	}
	if !waitForKey(t, signerd.GetURL(), token, lsigAddr, 10*time.Second) {
		t.Fatalf("signer did not reload generated lifecycle LSig key %s", lsigAddr)
	}

	if err := funder.FundMicroAlgosAndWait(lsigAddr, 500_000); err != nil {
		t.Fatalf("failed to fund lifecycle generic LSig account: %v", err)
	}

	inUseDisable, err := apadmin.DeactivateKeyType(keyType)
	if err != nil {
		t.Fatalf("failed to send in-use deactivate IPC message: %v", err)
	}
	if inUseDisable.Success || inUseDisable.Code != protocol.ResultCodeKeyTypeInUse {
		t.Fatalf("in-use deactivate result = %+v, want %s failure", inUseDisable, protocol.ResultCodeKeyTypeInUse)
	}

	output, err := apstore.RunWithInput("y\n", "template", "remove", keyType)
	if err == nil {
		t.Fatalf("template remove succeeded while key still existed; output:\n%s", output)
	}
	if !strings.Contains(output, "key(s) still use it") {
		t.Fatalf("template remove output = %q, want in-use context", output)
	}

	// The account itself already exists, so the client reaches the on-chain
	// template rejection instead of rejecting a sub-minimum new-account send.
	assertLogicSigSendRejected(t, apshellForSigner(t, signerd), lsigAddr, lsigAddr)

	apshell := apshellForSigner(t, signerd)
	closeTxID, err := apshell.CloseAccount(lsigAddr, funder.GetAddress())
	if err != nil {
		t.Fatalf("failed to close lifecycle generic LSig: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(closeTxID, 10); err != nil {
		t.Fatalf("lifecycle generic LSig close transaction failed to confirm: %v", err)
	}

	token = readSignerToken(t, signerd)
	signerClient = signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	if _, err := signerClient.AdminDeleteKey(lsigAddr); err != nil {
		t.Fatalf("failed to delete lifecycle generic LSig key %s: %v", lsigAddr, err)
	}
	if !waitForKeyMissing(t, signerd.GetURL(), token, lsigAddr, 10*time.Second) {
		t.Fatalf("signer still reports deleted lifecycle LSig key %s", lsigAddr)
	}

	finalDisable, err := apadmin.DeactivateKeyType(keyType)
	if err != nil {
		t.Fatalf("failed to send final deactivate IPC message: %v", err)
	}
	if !finalDisable.Success || !finalDisable.Removed {
		t.Fatalf("final deactivate result = %+v, want success with state change", finalDisable)
	}

	if output, err := apstore.RunWithInput("y\n", "template", "remove", keyType); err != nil {
		t.Fatalf("failed to remove unused lifecycle template: %v\noutput:\n%s", err, output)
	}
}

func TestComposedDSATemplateLifecycleAllowsSignAndRemove(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping funding-backed composed DSA lifecycle test")
	}

	lockOnDisconnect := false
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	family := fmt.Sprintf("falcon1024-lifecycle-closeback-%d", time.Now().UnixNano())
	keyType := integrationTemplateKeyType(family)
	templatePath := writeComposedFundingClosebackTemplate(t, family, funder.GetAddress())

	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, env.SignerDataDir))
	apstore := harness.NewApStoreHarness(t, env.SignerDataDir)
	mustImportTemplateViaApstore(t, env.SignerDataDir, apstore, templatePath, "composed DSA lifecycle")

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	disableResult, err := apadmin.DeactivateKeyType(keyType)
	if err != nil {
		t.Fatalf("failed to send initial composed deactivate IPC message: %v", err)
	}
	if !disableResult.Success || !disableResult.Removed {
		t.Fatalf("initial composed deactivate result = %+v, want success with state change", disableResult)
	}

	if err := apadmin.ActivateKeyType(keyType); err != nil {
		t.Fatalf("failed to re-enable composed template key type over IPC: %v", err)
	}

	token := readSignerToken(t, signerd)
	signerClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	resp, err := signerClient.AdminGenerate(keyType, nil)
	if err != nil {
		t.Fatalf("failed to generate composed DSA LSig: %v", err)
	}
	lsigAddr := resp.Address
	if lsigAddr == "" {
		t.Fatal("admin generate returned empty composed DSA LSig address")
	}
	if !waitForKey(t, signerd.GetURL(), token, lsigAddr, 10*time.Second) {
		t.Fatalf("signer did not reload generated composed DSA LSig key %s", lsigAddr)
	}

	if err := funder.FundMicroAlgosAndWait(lsigAddr, 700_000); err != nil {
		t.Fatalf("failed to fund composed DSA LSig account: %v", err)
	}

	inUseDisable, err := apadmin.DeactivateKeyType(keyType)
	if err != nil {
		t.Fatalf("failed to send in-use composed deactivate IPC message: %v", err)
	}
	if inUseDisable.Success || inUseDisable.Code != protocol.ResultCodeKeyTypeInUse {
		t.Fatalf("in-use composed deactivate result = %+v, want %s failure", inUseDisable, protocol.ResultCodeKeyTypeInUse)
	}

	output, err := apstore.RunWithInput("y\n", "template", "remove", keyType)
	if err == nil {
		t.Fatalf("composed template remove succeeded while key still existed; output:\n%s", output)
	}
	if !strings.Contains(output, "key(s) still use it") {
		t.Fatalf("composed template remove output = %q, want in-use context", output)
	}

	assertLogicSigSendRejected(t, apshellForSigner(t, signerd), lsigAddr, lsigAddr)

	apshell := apshellForSigner(t, signerd)
	sendTxID, err := apshell.SendTransaction(lsigAddr, funder.GetAddress(), 0.05)
	if err != nil {
		t.Fatalf("failed to send from composed DSA LSig: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(sendTxID, 10); err != nil {
		t.Fatalf("composed DSA LSig send transaction failed to confirm: %v", err)
	}

	closeTxID, err := apshell.CloseAccount(lsigAddr, funder.GetAddress())
	if err != nil {
		t.Fatalf("failed to close composed DSA LSig: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(closeTxID, 10); err != nil {
		t.Fatalf("composed DSA LSig close transaction failed to confirm: %v", err)
	}

	token = readSignerToken(t, signerd)
	signerClient = signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	if _, err := signerClient.AdminDeleteKey(lsigAddr); err != nil {
		t.Fatalf("failed to delete composed DSA LSig key %s: %v", lsigAddr, err)
	}
	if !waitForKeyMissing(t, signerd.GetURL(), token, lsigAddr, 10*time.Second) {
		t.Fatalf("signer still reports deleted composed DSA LSig key %s", lsigAddr)
	}

	finalDisable, err := apadmin.DeactivateKeyType(keyType)
	if err != nil {
		t.Fatalf("failed to send final composed deactivate IPC message: %v", err)
	}
	if !finalDisable.Success || !finalDisable.Removed {
		t.Fatalf("final composed deactivate result = %+v, want success with state change", finalDisable)
	}

	if output, err := apstore.RunWithInput("y\n", "template", "remove", keyType); err != nil {
		t.Fatalf("failed to remove unused composed template: %v\noutput:\n%s", err, output)
	}
}

func writeGenericAllowlistTemplate(t *testing.T, family string) string {
	t.Helper()

	templatePath := filepath.Join(t.TempDir(), "generic-allowlist.yaml")
	templateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Integration Allowlist"
description: "Integration test template that permits payments and close-out to allowlisted addresses"

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 10
    label: "Recipients"
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
		t.Fatalf("failed to write generic allowlist template: %v", err)
	}
	return templatePath
}

func writeGenericFundingClosebackTemplate(t *testing.T, family, fundingAddress string) string {
	t.Helper()

	templatePath := filepath.Join(t.TempDir(), "generic-funding-closeback.yaml")
	templateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 3
template_type: generic
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Integration Funding Closeback"
description: "Integration test template that permits payments and close-out only to the funding account"

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

  txn Receiver
  addr %s
  ==
  assert

  txn CloseRemainderTo
  global ZeroAddress
  ==
  txn CloseRemainderTo
  addr %s
  ==
  ||
  assert

  int 1
  return
`, integrationTemplatePublisher, family, fundingAddress, fundingAddress)
	if err := os.WriteFile(templatePath, []byte(templateYAML), 0o600); err != nil {
		t.Fatalf("failed to write generic funding closeback template: %v", err)
	}
	return templatePath
}

func writeComposedFundingClosebackTemplate(t *testing.T, family, fundingAddress string) string {
	t.Helper()

	templatePath := filepath.Join(t.TempDir(), "composed-funding-closeback.yaml")
	templateYAML := fmt.Sprintf(`schema_version: 1
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: %s
family: %s
version: 1
display_name: "Integration Falcon Closeback"
description: "Integration test Falcon-composed template that permits payments and close-out only to the funding account"

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
  addr %s
  ==
  assert

  txn CloseRemainderTo
  global ZeroAddress
  ==
  txn CloseRemainderTo
  addr %s
  ==
  ||
  assert
`, integrationTemplatePublisher, family, fundingAddress, fundingAddress)
	if err := os.WriteFile(templatePath, []byte(templateYAML), 0o600); err != nil {
		t.Fatalf("failed to write composed funding closeback template: %v", err)
	}
	return templatePath
}

func assertGenericAllowlistRekeyRejected(
	t *testing.T,
	apshell *harness.ApshellHarness,
	testnet *harness.TestnetConfig,
	lsigAddr string,
	rekeyTarget string,
) {
	t.Helper()

	output, err := apshell.RunWithInput(fmt.Sprintf("rekey %s to %s\nquit\n", lsigAddr, rekeyTarget))
	lowerOutput := strings.ToLower(output)
	if !strings.Contains(lowerOutput, "rekey transaction failed") &&
		!strings.Contains(lowerOutput, "rejected by logic") {
		t.Fatalf("expected generic allowlist LSig rekey attempt to fail on chain: %v\noutput:\n%s", err, output)
	}
	if strings.Contains(lowerOutput, "rekey transaction submitted:") {
		t.Fatalf("expected generic allowlist LSig rekey not to be accepted, output:\n%s", output)
	}

	accountInfo, err := testnet.Client.AccountInformation(lsigAddr).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to inspect generic allowlist LSig account after rejected rekey: %v", err)
	}
	if accountInfo.AuthAddr != "" {
		t.Fatalf("expected generic allowlist LSig account to remain unrekeyed, got auth address %s", accountInfo.AuthAddr)
	}
}

func assertLogicSigSendRejected(t *testing.T, apshell *harness.ApshellHarness, from, to string) {
	t.Helper()

	output, err := apshell.RunWithInput(fmt.Sprintf("send 0.050000 algo from %s to %s\nquit\n", from, to))
	lowerOutput := strings.ToLower(output)
	if strings.Contains(lowerOutput, "transaction submitted:") || strings.Contains(lowerOutput, "transaction id:") {
		t.Fatalf("expected generic allowlist send to %s not to be submitted, output:\n%s", to, output)
	}
	if !strings.Contains(lowerOutput, "transaction failed") &&
		!strings.Contains(lowerOutput, "rejected by logic") &&
		!strings.Contains(lowerOutput, "logic eval") &&
		!strings.Contains(lowerOutput, "rejected") {
		t.Fatalf("expected generic allowlist send to fail on chain: %v\noutput:\n%s", err, output)
	}
}

func apshellForSigner(t *testing.T, signerd *harness.SignerHarness) *harness.ApshellHarness {
	t.Helper()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy token: %v", err)
	}
	return apshell
}

func TestGenericLSigRegenerationProducesSameAddress(t *testing.T) {
	lockOnDisconnect := false
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	installHTLCTemplate(t, env.SignerDataDir)

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	token := readSignerToken(t, signerd)
	signerClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), token)

	params := map[string]string{
		"hash":           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"recipient":      integrationBurnAddress,
		"refund_address": integrationBurnAddress,
		"timeout_round":  "999999999",
	}

	// Generate the key
	resp, err := signerClient.AdminGenerate("aplane.htlc.v1", params)
	if err != nil {
		t.Fatalf("failed to generate aplane.htlc.v1: %v", err)
	}
	if resp.Address == "" {
		t.Fatal("admin generate returned empty address")
	}
	originalAddress := resp.Address
	t.Logf("Generated aplane.htlc.v1 address: %s", originalAddress)

	if !waitForKey(t, signerd.GetURL(), token, originalAddress, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", originalAddress)
	}

	// Delete the key
	if _, err := signerClient.AdminDeleteKey(originalAddress); err != nil {
		t.Fatalf("failed to delete key %s: %v", originalAddress, err)
	}
	t.Logf("Deleted key %s", originalAddress)

	// Regenerate with the same params
	resp2, err := signerClient.AdminGenerate("aplane.htlc.v1", params)
	if err != nil {
		t.Fatalf("failed to regenerate aplane.htlc.v1: %v", err)
	}
	if resp2.Address == "" {
		t.Fatal("admin regenerate returned empty address")
	}
	t.Logf("Regenerated aplane.htlc.v1 address: %s", resp2.Address)

	// Clean up the regenerated key
	t.Cleanup(func() {
		if _, err := signerClient.AdminDeleteKey(resp2.Address); err != nil {
			t.Logf("failed to delete regenerated key %s: %v", resp2.Address, err)
		}
	})

	if resp2.Address != originalAddress {
		t.Fatalf("regenerated address %s does not match original %s", resp2.Address, originalAddress)
	}
}

// TestFalconAllowlistRecoveryProducesSameAddress was previously an end-to-end
// round-trip exercising export of the generated mnemonic followed by re-import.
// Mnemonic export is now disabled in the admin protocol so the test can no
// longer be expressed end-to-end; recovery determinism for falcon1024 hybrids
// is exercised at the lsig/falcon1024 layer, and end-to-end recovery is now
// covered by backup/restore in test/integration/backup_portability_test.go.

func generateGenericLSigWithShell(t *testing.T, apshell *harness.ApshellHarness, keyType, recipient string) string {
	t.Helper()

	output, err := apshell.RunWithInput(fmt.Sprintf("generate %s recipients=%s\nquit\n", keyType, recipient))
	if err != nil {
		t.Fatalf("failed to generate generic LSig with apshell: %v\noutput:\n%s", err, output)
	}
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "Generated") || !strings.Contains(line, "key:") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if len(field) != 58 {
				continue
			}
			if _, err := types.DecodeAddress(field); err == nil {
				return field
			}
		}
	}
	t.Fatalf("could not find generated address in apshell output:\n%s", output)
	return ""
}
