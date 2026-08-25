// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"github.com/aplane-algo/aplane/internal/productmode"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

func TestApadminChangepassUpdatesIdentityUnlockHelperAndSignerRestarts(t *testing.T) {
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})
	currentPassphrase := mustReadPassphrase(t, env.SignerDataDir)

	passFileBinary := buildPassFileHelper(t)
	identityPassphrasePath := filepath.Join(env.SignerDataDir, "identities", productmode.IdentityID, "passphrase")
	if err := os.WriteFile(identityPassphrasePath, []byte(currentPassphrase), 0o600); err != nil {
		t.Fatalf("failed to seed identity passphrase file: %v", err)
	}
	if err := unlockconfig.SaveUnlockConfig(env.SignerDataDir, &unlockconfig.UnlockConfig{
		PassphraseCommandArgv: []string{passFileBinary, identityPassphrasePath},
	}); err != nil {
		t.Fatalf("failed to write identity unlock config: %v", err)
	}

	newPassphrase := "rotated-passphrase-for-integration"
	apadmin := harness.NewApAdminHarness(t, env.SignerDataDir)
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer before changepass: %v", err)
	}
	var (
		localnet        *harness.TestnetConfig
		rotationAddress string
	)
	if harness.IntegrationNetwork() == harness.IntegrationNetworkLocalnet {
		var networkErr error
		localnet, networkErr = harness.NewTestnetConfig()
		if networkErr != nil {
			_ = signerd.Stop()
			t.Fatalf("connect to LocalNet for rotation acceptance: %v", networkErr)
		}
		beforeToken := readSignerToken(t, signerd)
		beforeClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), beforeToken)
		generated, generateErr := beforeClient.AdminGenerate("ed25519", nil)
		if generateErr != nil {
			_ = signerd.Stop()
			t.Fatalf("generate rotation acceptance key: %v", generateErr)
		}
		rotationAddress = generated.Address
		funder, funderErr := harness.NewFundTestAccount(localnet.Client)
		if funderErr != nil {
			_ = signerd.Stop()
			t.Fatalf("create LocalNet rotation acceptance funder: %v", funderErr)
		}
		if fundErr := funder.FundMicroAlgosAndWait(rotationAddress, 300_000); fundErr != nil {
			_ = signerd.Stop()
			t.Fatalf("fund rotation acceptance key: %v", fundErr)
		}
	}
	output, err := apadmin.RunWithInput(currentPassphrase+"\n"+newPassphrase+"\n"+newPassphrase+"\ny\n", "changepass")
	if err != nil {
		_ = signerd.Stop()
		t.Fatalf("apadmin changepass failed: %v\nOutput: %s", err, output)
	}
	if !strings.Contains(output, "passphrase change complete") {
		_ = signerd.Stop()
		t.Fatalf("changepass output did not report completion:\n%s", output)
	}
	if err := signerd.Stop(); err != nil {
		t.Fatalf("failed to stop signer after changepass: %v", err)
	}

	gotPassphrase, err := os.ReadFile(identityPassphrasePath)
	if err != nil {
		t.Fatalf("failed to read updated identity passphrase file: %v", err)
	}
	if string(gotPassphrase) != newPassphrase {
		t.Fatalf("identity passphrase helper was not updated")
	}

	signerd = harness.NewSignerHarness(t)
	signerd.OmitTestPassphraseEnv()
	if err := signerd.Start(); err != nil {
		t.Fatalf("apsigner failed to restart after changepass: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	token := readSignerToken(t, signerd)
	client := signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	keys, err := client.GetKeys()
	if err != nil {
		t.Fatalf("failed to fetch keys after restart: %v", err)
	}
	if keys.Locked {
		t.Fatal("signer started locked; expected passphrase command auto-unlock")
	}
	if localnet != nil {
		sp, err := localnet.GetSuggestedParams()
		if err != nil {
			t.Fatalf("get LocalNet params after rotation: %v", err)
		}
		response, err := client.RequestGroupSign([]signerapi.SignRequest{{
			AuthAddress: rotationAddress,
			TxnBytesHex: mustUnsignedPaymentTxnHex(
				t,
				sp,
				rotationAddress,
				integrationBurnAddress,
				0,
				"post-rotation-store-acceptance",
			),
		}})
		if err != nil {
			t.Fatalf("sign with rotated store key: %v", err)
		}
		txids := submitSignedTxnGroup(t, localnet, response.Signed)
		if len(txids) != 1 {
			t.Fatalf("post-rotation submission returned %d txids, want 1", len(txids))
		}
		if _, err := localnet.WaitForConfirmation(txids[0], 10); err != nil {
			t.Fatalf("post-rotation transaction did not confirm: %v", err)
		}
	}

	logs, err := signerd.GetLogs()
	if err != nil {
		t.Fatalf("failed to read signer logs: %v", err)
	}
	if !strings.Contains(logs, "passphrase loaded via passphrase command") {
		t.Fatalf("signer logs do not show passphrase command startup:\n%s", logs)
	}
}

func buildPassFileHelper(t *testing.T) string {
	t.Helper()

	projectRoot := findIntegrationProjectRoot(t)
	helperPath := filepath.Join(t.TempDir(), "appass-file")
	cmd := exec.Command("go", "build", "-o", helperPath, "./cmd/appass-file")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build appass-file helper: %v\nOutput: %s", err, output)
	}
	if err := os.Chmod(helperPath, 0o755); err != nil {
		t.Fatalf("failed to set appass-file helper mode: %v", err)
	}
	return helperPath
}

func findIntegrationProjectRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("failed to find project root")
		}
		dir = parent
	}
}
