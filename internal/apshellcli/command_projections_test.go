// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
)

// Every MCP result's warnings field has one shape: a list of objects with the
// code a client matches on and the message.
func TestMCPWarningsAreCodeAndMessageObjects(t *testing.T) {
	warnings := []apshellapp.Warning{{Code: "recipient_lookalike", Message: "looks like alice"}}
	want := `[{"code":"recipient_lookalike","message":"looks like alice"}]`
	for name, projection := range map[string]any{
		"send":  projectSendResult(&apshellapp.SendExecutionResult{Warnings: warnings}, false),
		"sweep": projectSweepResult(&apshellapp.SweepCommandResult{Warnings: warnings}, false),
		"rekey": rekeyProjection{Mode: "transaction", Warnings: projectWarnings(warnings)},
		"generate": projectGeneratedKey(&apshellapp.GenerateKeyCommandResult{
			Warnings: []string{"looks like alice"},
		}),
	} {
		data, err := json.Marshal(projection)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := string(fields["warnings"])
		if name == "generate" {
			want := `[{"code":"signer_advice","message":"looks like alice"}]`
			if got != want {
				t.Fatalf("%s warnings = %s, want %s", name, got, want)
			}
			continue
		}
		if got != want {
			t.Fatalf("%s warnings = %s, want %s", name, got, want)
		}
	}
}
