// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
)

// A validate in which every item failed fails the command: the REPL draws
// each item and returns the failure, and a script stops on it. MCP keeps
// the structured result, each item with its error and submission.
func TestValidateWhoseItemsAllFailed(t *testing.T) {
	f := newSubmitFixture(t, nodeRefusesSubmit)
	var out bytes.Buffer
	f.state.SetOutput(&out)
	account := f.a.Address.String()

	err := f.state.executeCommand(Command{Name: "validate", Args: []string{account}})
	if err == nil || err.Error() != "all 1 validation(s) failed" {
		t.Fatalf("validate error = %v, want all 1 failed", err)
	}
	if !strings.Contains(out.String(), "✗ Failed:") {
		t.Fatalf("the failed item was not drawn:\n%s", out.String())
	}

	err = f.state.runScript([]string{writeScript(t, "validate "+account, "simulate on")})
	if err == nil || err.Error() != "script execution stopped at line 1" {
		t.Fatalf("runScript() error = %v, want the script stopped at the validate", err)
	}
	if f.state.app().IsSimulateEnabled() {
		t.Fatal("the script went on past the failed validate")
	}

	result := mcpExecuteCommand(f.state, Command{Name: "validate", Args: []string{account}})
	if result.IsError {
		t.Fatalf("MCP validate is an error result %q, want the structured result", mcpResultText(t, result))
	}
	var projection validateProjection
	if err := json.Unmarshal([]byte(mcpResultText(t, result)), &projection); err != nil {
		t.Fatal(err)
	}
	if projection.FailureCount != 1 || len(projection.Items) != 1 || projection.Items[0].Error == "" ||
		projection.Items[0].Submission == nil || projection.Items[0].Submission.State != "rejected" {
		t.Fatalf("MCP validate = %s, want the failed item with its submission", mcpResultText(t, result))
	}
}

// A set in which some validations passed is not a failure of the command.
func TestValidateWhoseItemsPartlyFailed(t *testing.T) {
	f := newSubmitFixture(t, nodeConfirms)
	foreign := crypto.GenerateAccount().Address.String() // the signer holds no key for it
	f.eng.SetCache.Sets = map[string][]string{"pair": {f.a.Address.String(), foreign}}
	var out bytes.Buffer
	f.state.SetOutput(&out)

	if err := f.state.executeCommand(Command{Name: "validate", Args: []string{"@pair"}}); err != nil {
		t.Fatalf("validate @pair error = %v, want the command to succeed\n%s", err, out.String())
	}
	if text := out.String(); !strings.Contains(text, "Successful: 1/2") || !strings.Contains(text, "Failed: 1/2") {
		t.Fatalf("validate @pair drew:\n%s\nwant one passed and one failed", text)
	}
}
