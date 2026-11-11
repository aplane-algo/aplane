// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

// A rekey's opening lines go out on the live path, when the app announces
// them before signing, and the result rendered afterwards does not repeat
// them.
func TestRekeyLinesAreAnnouncedLiveAndNotRepeated(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	var live []string
	r := &REPLState{
		App:          apshellapp.New(eng, config.DefaultConfig(), t.TempDir()),
		ProgressLine: func(line string) { live = append(live, line) },
	}
	result := &apshellapp.RekeyCommandResult{
		From: "FROM", To: "TO", TxID: "TXID",
		PreSubmitLines: []string{"Rekeying account {from} to {to}...", "WARNING: read me first"},
	}

	r.announceRekey(result)
	if len(live) != 2 || live[0] != "Rekeying account FROM to TO..." || live[1] != "WARNING: read me first" {
		t.Fatalf("live lines = %q", live)
	}

	rendered, err := rekeyTransactionResult(r, result, true, false, "Rekey transaction submitted")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := rendered.RenderText(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "WARNING: read me first") {
		t.Fatalf("the result repeats the announcement:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "Rekey transaction submitted: TXID") {
		t.Fatalf("the result lacks the submission line:\n%s", out.String())
	}
}
