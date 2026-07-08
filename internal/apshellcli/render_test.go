// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestKeysResultRenderTextOmitsCounterAndIndent(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewInitializedEngine("testnet", &cfg, t.TempDir())
	if err != nil {
		t.Fatalf("NewInitializedEngine() error = %v", err)
	}

	var out bytes.Buffer
	state := &REPLState{
		Out: &out,
		App: apshellapp.New(eng, cfg, t.TempDir()),
	}
	result := &KeysResult{Keys: appresult.Keys{Keys: []appresult.KeyInfo{
		{Address: "ADDRONE", KeyType: "aplane.falcon1024.v1"},
		{Address: "ADDRTWO", KeyType: "ed25519"},
		{Address: "ADDRTHREE", KeyType: "mytemplate-v1", TemplateProvenanceStatus: "conflict"},
	}}}

	result.RenderText(&out, state)

	got := out.String()
	if strings.Contains(got, "Signable accounts:") {
		t.Fatalf("RenderText() included removed counter:\n%s", got)
	}
	if strings.Contains(got, "\n\n") {
		t.Fatalf("RenderText() included an extra blank line:\n%s", got)
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.HasPrefix(line, "  ") {
			t.Fatalf("RenderText() line has leading indent: %q\nfull output:\n%s", line, got)
		}
	}
	if !strings.Contains(got, "ADDRONE [aplane.falcon1024.v1]\n") ||
		!strings.Contains(got, "ADDRTWO [ed25519]\n") ||
		!strings.Contains(got, "ADDRTHREE [mytemplate-v1] [template mismatch]\n") {
		t.Fatalf("RenderText() missing key rows:\n%s", got)
	}
}

func TestPluginRenderTextLabelsTxIDsAsSimulatedWhenSimulateModeIsEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	var out bytes.Buffer
	state := &REPLState{
		Out: &out,
		App: apshellapp.New(eng, cfg, t.TempDir()),
	}
	state.app().SetSimulateMode(true)
	result := &PluginResult{Plugin: appresult.Plugin{
		Plugin:  "reti",
		Success: true,
		TxIDs:   []string{"TX1"},
	}}

	result.RenderText(&out, state)

	got := out.String()
	if !strings.Contains(got, "Transaction(s) simulated successfully") {
		t.Fatalf("RenderText() output missing simulated label:\n%s", got)
	}
	if strings.Contains(got, "Transaction(s) submitted successfully") {
		t.Fatalf("RenderText() output used submitted label in simulate mode:\n%s", got)
	}
}
