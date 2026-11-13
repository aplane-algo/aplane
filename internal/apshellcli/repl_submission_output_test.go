// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// What the REPL prints after a failed submission is what it printed before
// submissions carried their outcome: the outcome is for MCP, and nothing of it
// reaches the REPL's output or makes it print an item's output twice. Each
// expected output was taken from main with these tests.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// replRun runs line in the REPL and returns what it printed and the error it
// returned, with the fixture's addresses and the IDs its signer signed
// replaced by names: {a}, {b}, {c}, {r}, and {id<group>.<index>}, and the
// test node's URL by {node}.
func (f *submitFixture) replRun(t *testing.T, state *REPLState, line string) (string, string) {
	t.Helper()
	var out bytes.Buffer
	state.SetOutput(&out)
	cmd, err := parseShellCommand(line)
	if err != nil {
		t.Fatal(err)
	}
	runErr := state.executeCommand(cmd)
	if runErr == nil {
		t.Fatalf("%s: no error, output %q", line, out.String())
	}
	replace := []string{f.a.Address.String(), "{a}", f.b.Address.String(), "{b}", f.c.Address.String(), "{c}", f.r.String(), "{r}"}
	for i, group := range f.signedIDs() {
		for j, id := range group {
			replace = append(replace, id, fmt.Sprintf("{id%d.%d}", i, j))
		}
	}
	names := strings.NewReplacer(replace...)
	normalize := func(s string) string { return testNodeURL.ReplaceAllString(names.Replace(s), "{node}") }
	return normalize(out.String()), normalize(runErr.Error())
}

var testNodeURL = regexp.MustCompile(`http://127\.0\.0\.1:[0-9]+`)

func wantREPL(t *testing.T, gotOut, gotErr, wantOut, wantErr string) {
	t.Helper()
	if gotOut != wantOut {
		t.Errorf("output:\n%s\nwant:\n%s", gotOut, wantOut)
	}
	if gotErr != wantErr {
		t.Errorf("error = %q, want %q", gotErr, wantErr)
	}
}

// A sweep in which every item failed prints each item's submission output
// once, in its item, and then the error.
func TestREPLSweepWhoseItemsAllFailedOutputIsUnchanged(t *testing.T) {
	f := newSubmitFixture(t, nodeDropsSubmit)
	out, errText := f.replRun(t, f.state, fmt.Sprintf("sweep algo from [%s %s] to %s", f.a.Address, f.c.Address, f.b.Address))
	if n := strings.Count(out, "Submitting to network..."); n != 2 {
		t.Errorf("submission output printed %d times, want once for each of the 2 items", n)
	}
	wantREPL(t, out, errText, replSweepAllFailed, "all 2 transaction(s) failed")
}

// js send() whose submission failed prints nothing the script did not print;
// the error is the exception's text.
func TestREPLJSSendFailureOutputIsUnchanged(t *testing.T) {
	f := newSubmitFixture(t, nodeDropsSubmit)
	out, errText := f.replRun(t, f.state, fmt.Sprintf("js send(%q, %q, 1000)", f.a.Address, f.b.Address))
	wantREPL(t, out, errText, "", replJSSendFailed)
}

// js plugin() whose step's submission failed prints the step's submission
// output once.
func TestREPLJSPluginStepFailureOutputIsUnchanged(t *testing.T) {
	f := newSubmitFixture(t, nodeDropsSubmit)
	txn, err := transaction.MakePaymentTxn(f.a.Address.String(), f.b.Address.String(), 1000, nil, "", types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 1900, GenesisHash: f.genesis, GenesisID: "testnet-v1.0", FlatFee: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, _ := scriptedPluginShellOnEngine(t, f.eng, map[string]any{
		"success": true, "message": "pay",
		"transactions": []map[string]any{{"type": "raw", "encoded": base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}},
	})
	state.DataDir = t.TempDir()
	state.CommandRegistry = state.initCommandRegistry()
	out, errText := f.replRun(t, state, `js plugin("wf", "start")`)
	if n := strings.Count(out, "Submitting to network..."); n != 1 {
		t.Errorf("submission output printed %d times, want once", n)
	}
	wantREPL(t, out, errText, replJSPluginFailed, replJSPluginError)
}

const replSweepAllFailed = `
Sweeping ALGO from 2 account(s) to {b} @ (leaving each its minimum balance)
============================================================

[1/2] Processing {a} @...

Submitting to network...
  ✗ transaction failed: failed to sign and submit: failed to submit transaction: Post "{node}/v2/transactions": EOF

[2/2] Processing {c} @...

Submitting to network...
  ✗ transaction failed: failed to sign and submit: failed to submit transaction: Post "{node}/v2/transactions": EOF

============================================================
Sweep complete: 0 succeeded, 2 failed
`

const replJSSendFailed = "send() error submitting transaction: failed to sign and submit: failed to submit transaction: Post \"{node}/v2/transactions\": EOF\n" +
	"\tat github.com/aplane-algo/aplane/internal/jsapi.(*API).hostCall.func1 (native)\n\tat <eval>:1:5(4)\n"

const replJSPluginFailed = `
DRAFT: plugin-built transaction(s); apsigner sets the final fees and group ID, and its policy and approval apply to the final group
1 transaction(s):
  [1] apsigner      pay
        Payment: 0.001000 ALGO
          From: {a}
          To:   {b}
          Fee: 0.001000 ALGO
          Network: testnet
          GenesisID: testnet-v1.0
Fees paid by APlane-managed accounts: 0.001000 ALGO

Submitting to network...
`

const replJSPluginError = "plugin() error: failed to submit transaction: Post \"{node}/v2/transactions\": EOF\n" +
	"\tat github.com/aplane-algo/aplane/internal/jsapi.(*API).hostCall.func1 (native)\n\tat <eval>:1:7(3)\n"
