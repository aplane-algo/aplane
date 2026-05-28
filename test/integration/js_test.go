// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

type jsHarnessEnv struct {
	testnet     *harness.TestnetConfig
	funder      *harness.FundTestAccount
	signerd     *harness.SignerHarness
	apadmin     *harness.ApAdminHarness
	apshell     *harness.ApshellHarness
	token       string
	fundingAddr string
}

func setupJavaScriptHarness(t *testing.T) *jsHarnessEnv {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping JavaScript integration test in short mode")
	}
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set")
	}

	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	fundingAddr, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC"))
	if err != nil {
		t.Fatalf("failed to import funding account into signer: %v", err)
	}

	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, fundingAddr, 10*time.Second) {
		t.Fatalf("signer did not reload imported funding key %s", fundingAddr)
	}

	return &jsHarnessEnv{
		testnet:     testnet,
		funder:      funder,
		signerd:     signerd,
		apadmin:     apadmin,
		apshell:     apshell,
		token:       token,
		fundingAddr: fundingAddr,
	}
}

func runApshellJS(t *testing.T, apshell *harness.ApshellHarness, code string) string {
	return runApshellSession(t, apshell, nil, code)
}

func runApshellSession(t *testing.T, apshell *harness.ApshellHarness, commands []string, jsCode string) string {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "script.js")
	if err := os.WriteFile(scriptPath, []byte(jsCode), 0o600); err != nil {
		t.Fatalf("failed to write JS script: %v", err)
	}

	var input strings.Builder
	input.WriteString("connect\n")
	for _, cmd := range commands {
		input.WriteString(cmd)
		input.WriteByte('\n')
	}
	input.WriteString(fmt.Sprintf("js %s\nquit\n", scriptPath))

	output, err := apshell.RunWithInput(input.String())
	if err != nil {
		t.Fatalf("apshell JS REPL run failed: %v", err)
	}
	return output
}

func decodeJSONLine[T any](t *testing.T, output string) T {
	t.Helper()

	var out T
	line := findJSONLine(output)
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("failed to decode JSON output %q: %v", output, err)
	}
	return out
}

func TestJavaScriptSignerQueries(t *testing.T) {
	env := setupJavaScriptHarness(t)

	addr, err := env.apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate JS test key: %v", err)
	}
	if !waitForKey(t, env.signerd.GetURL(), env.token, addr, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", addr)
	}

	output := runApshellJS(t, env.apshell, fmt.Sprintf(
		`print(JSON.stringify({network: network(), connected: connected(), types: keyTypes().map(k => k.keyType).sort(), keys: keys().map(k => k.address).sort(), signable: signableAddresses().sort(), funding: canSignFor(%q)}));`,
		env.fundingAddr,
	))

	result := decodeJSONLine[struct {
		Network   string   `json:"network"`
		Connected bool     `json:"connected"`
		Types     []string `json:"types"`
		Keys      []string `json:"keys"`
		Signable  []string `json:"signable"`
		Funding   struct {
			CanSign bool `json:"canSign"`
			IsLSig  bool `json:"isLsig"`
		} `json:"funding"`
	}](t, output)

	if result.Network != harness.IntegrationNetwork() {
		t.Fatalf("network = %q, want %s", result.Network, harness.IntegrationNetwork())
	}
	if !result.Connected {
		t.Fatal("expected connected() to be true")
	}
	if !containsString(result.Types, "ed25519") {
		t.Fatalf("keyTypes() = %#v, want ed25519", result.Types)
	}
	if !containsString(result.Keys, env.fundingAddr) || !containsString(result.Keys, addr) {
		t.Fatalf("keys() = %#v, want funding and generated addresses", result.Keys)
	}
	if !containsString(result.Signable, env.fundingAddr) || !containsString(result.Signable, addr) {
		t.Fatalf("signableAddresses() = %#v, want funding and generated addresses", result.Signable)
	}
	if !result.Funding.CanSign || result.Funding.IsLSig {
		t.Fatalf("canSignFor() = %#v, want signer-backed non-lsig account", result.Funding)
	}
}

func TestJavaScriptTransactionFlows(t *testing.T) {
	env := setupJavaScriptHarness(t)

	sourceAddr, err := env.apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate source key: %v", err)
	}
	recipientAddr, err := env.apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}
	if !waitForKey(t, env.signerd.GetURL(), env.token, sourceAddr, 10*time.Second) {
		t.Fatalf("signer did not reload source key %s", sourceAddr)
	}
	if !waitForKey(t, env.signerd.GetURL(), env.token, recipientAddr, 10*time.Second) {
		t.Fatalf("signer did not reload recipient key %s", recipientAddr)
	}

	if err := env.funder.FundMicroAlgosAndWait(sourceAddr, 250_000); err != nil {
		t.Fatalf("failed to fund source account: %v", err)
	}

	output := runApshellJS(t, env.apshell, fmt.Sprintf(`
const validation = validate(%q);
print("validate=" + validation.txid);
const payment = send(%q, %q, algo(0.1));
print("send=" + payment.txid);
const closeout = close(%q, %q);
print("close=" + closeout.txid);
`, sourceAddr, sourceAddr, recipientAddr, sourceAddr, env.fundingAddr))

	if !strings.Contains(output, "validate=") {
		t.Fatalf("missing validate output:\n%s", output)
	}
	if !strings.Contains(output, "send=") {
		t.Fatalf("missing send output:\n%s", output)
	}
	if !strings.Contains(output, "close=") {
		t.Fatalf("missing close output:\n%s", output)
	}

	recipientBalance, err := env.testnet.GetAccountInfo(recipientAddr)
	if err != nil {
		t.Fatalf("failed to get recipient balance: %v", err)
	}
	if recipientBalance != 100_000 {
		t.Fatalf("recipient balance = %d, want 100000", recipientBalance)
	}
}

func TestJavaScriptSignAndRekeyFlows(t *testing.T) {
	env := setupJavaScriptHarness(t)

	rekeyedAddr, err := env.apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("failed to generate rekey target account: %v", err)
	}
	if !waitForKey(t, env.signerd.GetURL(), env.token, rekeyedAddr, 10*time.Second) {
		t.Fatalf("signer did not reload generated key %s", rekeyedAddr)
	}
	if err := env.funder.FundMicroAlgosAndWait(rekeyedAddr, 200_000); err != nil {
		t.Fatalf("failed to fund rekeyed account: %v", err)
	}

	sp, err := env.testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("failed to get suggested params: %v", err)
	}
	txn, err := transaction.MakePaymentTxn(env.fundingAddr, integrationBurnAddress, 0, []byte("js-sign"), "", sp)
	if err != nil {
		t.Fatalf("failed to build unsigned payment transaction: %v", err)
	}
	unsignedPath := filepath.Join(t.TempDir(), "unsigned.txn")
	if err := os.WriteFile(unsignedPath, []byte(base64.StdEncoding.EncodeToString(msgpack.Encode(txn))), 0o600); err != nil {
		t.Fatalf("failed to write unsigned transaction file: %v", err)
	}

	signOutput := runApshellJS(t, env.apshell, fmt.Sprintf(`print(JSON.stringify(sign(%q)));`, unsignedPath))
	signResult := decodeJSONLine[struct {
		TxIDs     []string `json:"txids"`
		Confirmed bool     `json:"confirmed"`
	}](t, signOutput)
	if len(signResult.TxIDs) != 1 || !signResult.Confirmed {
		t.Fatalf("sign() result = %#v, want one confirmed txid", signResult)
	}

	rekeyOutput := runApshellJS(t, env.apshell, fmt.Sprintf(`print(JSON.stringify(rekey(%q, %q)));`, rekeyedAddr, env.fundingAddr))
	rekeyResult := decodeJSONLine[struct {
		TxID      string `json:"txid"`
		Confirmed bool   `json:"confirmed"`
	}](t, rekeyOutput)
	if rekeyResult.TxID == "" || !rekeyResult.Confirmed {
		t.Fatalf("rekey() result = %#v, want confirmed txid", rekeyResult)
	}

	isRekeyedOutput := runApshellSession(t, env.apshell, []string{"rekey refresh"}, fmt.Sprintf(`print(JSON.stringify(isRekeyed(%q)));`, rekeyedAddr))
	rekeyState := decodeJSONLine[struct {
		Rekeyed  bool   `json:"rekeyed"`
		AuthAddr string `json:"authAddr"`
	}](t, isRekeyedOutput)
	if !rekeyState.Rekeyed || rekeyState.AuthAddr != env.fundingAddr {
		t.Fatalf("isRekeyed() after rekey = %#v, want authAddr %s", rekeyState, env.fundingAddr)
	}

	unrekeyOutput := runApshellJS(t, env.apshell, fmt.Sprintf(`print(JSON.stringify(unrekey(%q)));`, rekeyedAddr))
	unrekeyResult := decodeJSONLine[struct {
		TxID      string `json:"txid"`
		Confirmed bool   `json:"confirmed"`
	}](t, unrekeyOutput)
	if unrekeyResult.TxID == "" || !unrekeyResult.Confirmed {
		t.Fatalf("unrekey() result = %#v, want confirmed txid", unrekeyResult)
	}

	isUnrekeyedOutput := runApshellSession(t, env.apshell, []string{"rekey refresh"}, fmt.Sprintf(`print(JSON.stringify(isRekeyed(%q)));`, rekeyedAddr))
	unrekeyState := decodeJSONLine[struct {
		Rekeyed  bool   `json:"rekeyed"`
		AuthAddr string `json:"authAddr"`
	}](t, isUnrekeyedOutput)
	if unrekeyState.Rekeyed || unrekeyState.AuthAddr != "" {
		t.Fatalf("isRekeyed() after unrekey = %#v, want self-controlled account", unrekeyState)
	}

	// Close the funded account back to the funding account to recover algo
	closeOutput := runApshellJS(t, env.apshell, fmt.Sprintf(`print(JSON.stringify(close(%q, %q)));`, rekeyedAddr, env.fundingAddr))
	closeResult := decodeJSONLine[struct {
		TxID      string `json:"txid"`
		Confirmed bool   `json:"confirmed"`
	}](t, closeOutput)
	if closeResult.TxID == "" || !closeResult.Confirmed {
		t.Fatalf("close() result = %#v, want confirmed txid", closeResult)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func findJSONLine(output string) string {
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			return line
		}
	}
	return strings.TrimSpace(output)
}
