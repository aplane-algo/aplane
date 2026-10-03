// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/test/integration/harness"
)

var policySetSHA256Line = regexp.MustCompile(`(?m)^policy_set_sha256 ([0-9a-f]{64})$`)

// TestApadminPolicyCLIOnlineAndRescue drives the apadmin policy verbs on a
// signer node the way an operator does: status, export, check, diff, and
// apply against the running daemon, then the rescue forms against the
// stopped store. Signing shows that each applied policy is the one enforced.
func TestApadminPolicyCLIOnlineAndRescue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping policy integration test in short mode")
	}
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set")
	}

	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to integration network: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	fundingAddr, err := apadmin.ImportFundingKey(os.Getenv("TEST_FUNDING_MNEMONIC"))
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
	requirePolicyTestKeyLoaded(t, signerd, token, fundingAddr)

	dir := t.TempDir()
	writeFile := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write %s: %v", path, err)
		}
		return path
	}
	restrictive := describedPolicy(restrictiveAlgoPaymentPolicy(testnet.Network), "policy cli online restrictive")
	restrictivePath := writeFile("restrictive.json", restrictive)
	permissive := describedPolicy(permissiveIntegrationPolicy(), "policy cli online permissive")
	invalidPath := writeFile("invalid.json", `{"format":"aplane.signer-policy.v1","max_fee_microalgos":5}`)

	expectRejectedSend := func(context string) {
		t.Helper()
		_, err := apshell.SendTransaction(fundingAddr, fundingAddr, 0.1)
		if err == nil {
			t.Fatalf("%s: 0.1 ALGO self-send succeeded, want policy rejection", context)
		}
		if text := err.Error(); !strings.Contains(text, "policy engine rejected request") ||
			!strings.Contains(text, "max_algo_payment_exceeded") {
			t.Fatalf("%s: 0.1 ALGO self-send failed for unexpected reason:\n%s", context, text)
		}
	}

	// Read-only verbs against the running daemon.
	baseSHA := policyStatusSHA(t, apadmin)
	exported := runPolicy(t, apadmin, "", 0, "export")
	if !strings.Contains(exported.Stdout, `"aplane.signer-policy.v1"`) {
		t.Fatalf("policy export did not print the signer document:\n%s", exported.Stdout)
	}

	invalid := runPolicy(t, apadmin, "", 1, "check", invalidPath)
	if !strings.Contains(invalid.Stderr, "/max_fee_microalgos") || !strings.Contains(invalid.Stderr, "policy is invalid") ||
		strings.Contains(invalid.Stdout, "policy OK") {
		t.Fatalf("policy check of an invalid file:\nstdout: %s\nstderr: %s", invalid.Stdout, invalid.Stderr)
	}
	valid := runPolicy(t, apadmin, "", 0, "check", restrictivePath)
	if !strings.Contains(valid.Stdout, "policy OK") {
		t.Fatalf("policy check of a valid file: %s", valid.Stdout)
	}
	// Key coverage warnings belong to cosigner nodes only.
	if strings.Contains(valid.Stderr, "does not hold") {
		t.Fatalf("signer-node policy check printed a key coverage warning: %s", valid.Stderr)
	}
	if out := runPolicy(t, apadmin, restrictive, 0, "check", "-").Stdout; !strings.Contains(out, "policy OK") {
		t.Fatalf("policy check from stdin: %s", out)
	}

	diff := runPolicy(t, apadmin, "", 0, "diff", restrictivePath).Stdout
	if !strings.Contains(diff, "tightened") || !strings.Contains(diff, "/limits") || !strings.Contains(diff, "/description") {
		t.Fatalf("policy diff output:\n%s", diff)
	}

	// Without --yes and without a terminal, apply refuses.
	unconfirmed := runPolicy(t, apadmin, "", 1, "apply", restrictivePath)
	if !strings.Contains(unconfirmed.Stderr, "--yes") {
		t.Fatalf("unconfirmed apply error: %s", unconfirmed.Stderr)
	}
	removed := runPolicy(t, apadmin, "", 1, "remove", "--yes", "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ")
	if !strings.Contains(removed.Stderr, "only to cosigner nodes") {
		t.Fatalf("policy remove on a signer node: %s", removed.Stderr)
	}
	if sha := policyStatusSHA(t, apadmin); sha != baseSHA {
		t.Fatalf("read-only and refused verbs changed policy_set_sha256: %s -> %s", baseSHA, sha)
	}

	// Apply from a file: stored bytes are the file's, and the running daemon
	// enforces them without a restart.
	applied := runPolicy(t, apadmin, "", 0, "apply", "--yes", restrictivePath).Stdout
	restrictiveSHA := appliedPolicySHA(t, applied)
	if restrictiveSHA == baseSHA || policyStatusSHA(t, apadmin) != restrictiveSHA {
		t.Fatalf("apply reported %s; base %s, status %s", restrictiveSHA, baseSHA, policyStatusSHA(t, apadmin))
	}
	if got := runPolicy(t, apadmin, "", 0, "export").Stdout; got != restrictive {
		t.Fatalf("policy export after apply is not the applied file:\n%s", got)
	}
	requirePolicyTestKeyLoaded(t, signerd, token, fundingAddr)
	expectRejectedSend("after online apply")

	if out := runPolicy(t, apadmin, "", 0, "apply", "--yes", restrictivePath).Stdout; !strings.Contains(out, "policy unchanged") {
		t.Fatalf("re-applying the active policy: %s", out)
	}
	if sha := policyStatusSHA(t, apadmin); sha != restrictiveSHA {
		t.Fatalf("re-applying the active policy changed policy_set_sha256 to %s", sha)
	}

	// Apply from stdin.
	applied = runPolicy(t, apadmin, permissive, 0, "apply", "--yes", "-").Stdout
	permissiveSHA := appliedPolicySHA(t, applied)
	if got := runPolicy(t, apadmin, "", 0, "export").Stdout; got != permissive {
		t.Fatalf("policy export after stdin apply is not the applied document:\n%s", got)
	}
	requirePolicyTestKeyLoaded(t, signerd, token, fundingAddr)
	txid, err := apshell.SendTransaction(fundingAddr, fundingAddr, 0.1)
	if err != nil {
		t.Fatalf("0.1 ALGO self-send failed after applying the permissive policy: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("0.1 ALGO self-send %s failed to confirm: %v", txid, err)
	}

	// Rescue mutations refuse while the daemon holds the store.
	rescueRestrictive := describedPolicy(restrictiveAlgoPaymentPolicy(testnet.Network), "policy cli rescue restrictive")
	rescuePath := writeFile("rescue.json", rescueRestrictive)
	refused := runPolicy(t, apadmin, "", 1, "rescue", "apply", "--yes", rescuePath)
	if !strings.Contains(refused.Stderr, "refusing offline policy apply") {
		t.Fatalf("rescue apply against a running daemon: %s", refused.Stderr)
	}
	if sha := policyStatusSHA(t, apadmin); sha != permissiveSHA {
		t.Fatalf("refused rescue apply changed policy_set_sha256 to %s", sha)
	}

	// Rescue verbs against the stopped store.
	stopSigner(t, signerd)
	if sha := policySHA(t, runPolicy(t, apadmin, "", 0, "rescue", "status").Stdout); sha != permissiveSHA {
		t.Fatalf("rescue status policy_set_sha256 = %s, want the last online value %s", sha, permissiveSHA)
	}
	if got := runPolicy(t, apadmin, "", 0, "rescue", "export").Stdout; got != permissive {
		t.Fatalf("rescue export is not the active document:\n%s", got)
	}
	invalid = runPolicy(t, apadmin, "", 1, "rescue", "check", invalidPath)
	if !strings.Contains(invalid.Stderr, "/max_fee_microalgos") {
		t.Fatalf("rescue check of an invalid file: %s", invalid.Stderr)
	}
	if out := runPolicy(t, apadmin, "", 0, "rescue", "diff", rescuePath).Stdout; !strings.Contains(out, "tightened") {
		t.Fatalf("rescue diff output:\n%s", out)
	}
	applied = runPolicy(t, apadmin, "", 0, "rescue", "apply", "--yes", rescuePath).Stdout
	rescueSHA := appliedPolicySHA(t, applied)
	if got := runPolicy(t, apadmin, "", 0, "rescue", "export").Stdout; got != rescueRestrictive {
		t.Fatalf("rescue export after apply is not the applied file:\n%s", got)
	}

	// The restarted daemon loads and enforces the rescue-applied policy.
	startSignerAndLoadKey(t, signerd, apadmin, token, fundingAddr)
	if sha := policyStatusSHA(t, apadmin); sha != rescueSHA {
		t.Fatalf("policy_set_sha256 after restart = %s, want the rescue-applied %s", sha, rescueSHA)
	}
	expectRejectedSend("after rescue apply and restart")
}

// describedPolicy adds a description to a signer policy document so that two
// otherwise equal documents are distinct applies with distinct bytes.
func describedPolicy(document, description string) string {
	return strings.Replace(document, "{", fmt.Sprintf("{\n  \"description\": %q,", description), 1)
}

func runPolicy(t *testing.T, apadmin *harness.ApAdminHarness, stdin string, wantExit int, args ...string) harness.PolicyResult {
	t.Helper()
	result, err := apadmin.RunPolicy(stdin, args...)
	if err != nil {
		t.Fatalf("%v\nstdout: %s\nstderr: %s", err, result.Stdout, result.Stderr)
	}
	if result.ExitCode != wantExit {
		t.Fatalf("apadmin policy %s exited %d, want %d\nstdout: %s\nstderr: %s",
			strings.Join(args, " "), result.ExitCode, wantExit, result.Stdout, result.Stderr)
	}
	return result
}

func policySHA(t *testing.T, output string) string {
	t.Helper()
	match := policySetSHA256Line.FindStringSubmatch(output)
	if match == nil {
		t.Fatalf("output has no policy_set_sha256 line:\n%s", output)
	}
	return match[1]
}

func policyStatusSHA(t *testing.T, apadmin *harness.ApAdminHarness) string {
	t.Helper()
	status := runPolicy(t, apadmin, "", 0, "status").Stdout
	if !strings.Contains(status, "signer policy") || !strings.Contains(status, "policy.json") {
		t.Fatalf("policy status output:\n%s", status)
	}
	return policySHA(t, status)
}

func appliedPolicySHA(t *testing.T, output string) string {
	t.Helper()
	if !strings.Contains(output, "policy applied as generation ") {
		t.Fatalf("apply did not report a new generation:\n%s", output)
	}
	return policySHA(t, output)
}
