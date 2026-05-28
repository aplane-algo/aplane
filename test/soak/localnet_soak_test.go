// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package soak_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/pkg/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

const (
	soakOptInEnv            = "APLANE_SOAK"
	soakDurationEnv         = "APLANE_SOAK_DURATION"
	soakMaxIterationsEnv    = "APLANE_SOAK_MAX_ITERATIONS"
	soakRestartEveryEnv     = "APLANE_SOAK_RESTART_EVERY"
	soakFalconEveryEnv      = "APLANE_SOAK_FALCON_EVERY"
	commandCoverageOptInEnv = "APLANE_COMMAND_COVERAGE"
	integrationBurnAddress  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	ed25519KeyType          = "ed25519"
	falcon1024V1KeyType     = "aplane.falcon1024.v1"
	defaultPaymentAlgos     = 0.01
	defaultFundMicroAlgos   = 300_000
	defaultConfirmMaxRounds = 20
)

func TestLocalNetSignerTransactionSoak(t *testing.T) {
	if os.Getenv(soakOptInEnv) != "1" {
		t.Skipf("set %s=1 to run the LocalNet soak test", soakOptInEnv)
	}
	if got := harness.IntegrationNetwork(); got != harness.IntegrationNetworkLocalnet {
		t.Fatalf("%s must be %q for soak tests, got %q", harness.IntegrationNetworkEnv, harness.IntegrationNetworkLocalnet, got)
	}

	duration := durationFromEnv(t, soakDurationEnv, 30*time.Minute)
	maxIterations := intFromEnv(t, soakMaxIterationsEnv, 0)
	restartEvery := intFromEnv(t, soakRestartEveryEnv, 0)
	falconEvery := intFromEnv(t, soakFalconEveryEnv, 5)
	if duration <= 0 && maxIterations <= 0 {
		t.Fatalf("%s must be positive when %s is unset or zero", soakDurationEnv, soakMaxIterationsEnv)
	}

	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to localnet algod: %v", err)
	}
	if network.Network != harness.IntegrationNetworkLocalnet {
		t.Fatalf("network = %q, want %q", network.Network, harness.IntegrationNetworkLocalnet)
	}

	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("create localnet funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	t.Cleanup(func() {
		if err := signerd.Stop(); err != nil {
			t.Logf("stop signer: %v", err)
		}
	})

	token := readSignerToken(t, signerd.GetTokenPath())
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("copy signer token to apshell fixture: %v", err)
	}

	startUnlock := func() {
		t.Helper()
		if err := apadmin.StartUnlockBackground(); err != nil {
			t.Fatalf("start background unlock: %v", err)
		}
	}
	stopUnlock := func() {
		t.Helper()
		apadmin.StopUnlockBackground()
	}
	startUnlock()
	t.Cleanup(stopUnlock)

	start := time.Now()
	deadline := time.Time{}
	if duration > 0 {
		deadline = start.Add(duration)
	}

	iterations := 0
	falconCycles := 0
	for maxIterations <= 0 || iterations < maxIterations {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			break
		}

		iterations++
		runAccountCycle(t, network, funder, apadmin, apshell, signerd.GetURL(), token, ed25519KeyType, "ed25519")
		if falconEvery > 0 && iterations%falconEvery == 0 {
			falconCycles++
			runAccountCycle(t, network, funder, apadmin, apshell, signerd.GetURL(), token, falcon1024V1KeyType, "falcon1024-v1")
		}

		if restartEvery > 0 && iterations%restartEvery == 0 {
			stopUnlock()
			if err := signerd.Stop(); err != nil {
				t.Fatalf("stop signer before restart at iteration %d: %v", iterations, err)
			}
			if err := signerd.Start(); err != nil {
				t.Fatalf("restart signer at iteration %d: %v", iterations, err)
			}
			token = readSignerToken(t, signerd.GetTokenPath())
			startUnlock()
			t.Logf("restarted signer after %d ed25519 iterations", iterations)
		}
	}
	if iterations == 0 {
		t.Fatal("soak test completed zero iterations")
	}
	t.Logf("completed localnet soak: ed25519_cycles=%d falcon_cycles=%d elapsed=%s", iterations, falconCycles, time.Since(start).Round(time.Second))
}

func runAccountCycle(
	t *testing.T,
	network *harness.TestnetConfig,
	funder *harness.FundTestAccount,
	apadmin *harness.ApAdminHarness,
	apshell *harness.ApshellHarness,
	signerURL string,
	token string,
	keyType string,
	label string,
) {
	t.Helper()

	address, err := apadmin.GenerateKeyWithType(keyType)
	if err != nil {
		t.Fatalf("generate %s key: %v", label, err)
	}
	waitForSignerKey(t, signerURL, token, address, 15*time.Second)

	if err := funder.FundMicroAlgosAndWait(address, defaultFundMicroAlgos); err != nil {
		t.Fatalf("fund %s account %s: %v", label, address, err)
	}

	txid, err := apshell.SendTransaction(address, integrationBurnAddress, defaultPaymentAlgos)
	if err != nil {
		t.Fatalf("send %s payment from %s: %v", label, address, err)
	}
	if _, err := network.WaitForConfirmation(txid, defaultConfirmMaxRounds); err != nil {
		t.Fatalf("wait for %s payment %s: %v", label, txid, err)
	}

	closeTxID, err := apshell.CloseAccount(address, funder.GetAddress())
	if err != nil {
		t.Fatalf("close %s account %s: %v", label, address, err)
	}
	if _, err := network.WaitForConfirmation(closeTxID, defaultConfirmMaxRounds); err != nil {
		t.Fatalf("wait for %s close transaction %s: %v", label, closeTxID, err)
	}

	if balance, err := network.GetAccountInfo(address); err == nil && balance != 0 {
		t.Fatalf("%s account %s retained %d microAlgos after close-out", label, address, balance)
	}
	if err := apadmin.DeleteGeneratedKey(address); err != nil {
		t.Fatalf("delete %s key %s after cycle: %v", label, address, err)
	}
	waitForSignerKeyMissing(t, signerURL, token, address, 15*time.Second)
	t.Logf("%s cycle ok: address=%s send=%s close=%s", label, address, txid, closeTxID)
}

func waitForSignerKey(t *testing.T, signerURL, token, address string, timeout time.Duration) {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		found, err := signerHasKey(client, signerURL, token, address)
		if err == nil && found {
			return
		}
		lastErr = err
		if lastErr == nil {
			lastErr = fmt.Errorf("key %s not listed yet", address)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for signer key %s after %s: %v", address, timeout, lastErr)
}

func waitForSignerKeyMissing(t *testing.T, signerURL, token, address string, timeout time.Duration) {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		found, err := signerHasKey(client, signerURL, token, address)
		if err == nil && !found {
			return
		}
		lastErr = err
		if lastErr == nil {
			lastErr = fmt.Errorf("key %s still listed", address)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for signer key %s to disappear after %s: %v", address, timeout, lastErr)
}

func signerHasKey(client *http.Client, signerURL, token, address string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, signerURL+"/keys", nil)
	if err != nil {
		return false, fmt.Errorf("build /keys request: %w", err)
	}
	req.Header.Set("Authorization", "aplane "+token)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		return false, fmt.Errorf("signer is locked")
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("/keys returned status %d", resp.StatusCode)
	}

	var keys signerapi.KeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return false, fmt.Errorf("decode /keys response: %w", err)
	}
	for _, key := range keys.Keys {
		if key.Address == address {
			return true, nil
		}
	}
	return false, nil
}

func readSignerToken(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read signer token %s: %v", path, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		t.Fatalf("signer token %s is empty", path)
	}
	return token
}

func durationFromEnv(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		t.Fatalf("%s must be a Go duration such as 30m or 2h, got %q: %v", name, raw, err)
	}
	return duration
}

func intFromEnv(t *testing.T, name string, fallback int) int {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		t.Fatalf("%s must be a non-negative integer, got %q", name, raw)
	}
	return value
}
