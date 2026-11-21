// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

const tokenFixtureKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

func roleNode(t *testing.T, role noderole.Role, tokens map[string][]string) *NodeContext {
	t.Helper()
	ctx, err := policycontext.New(role, apconfig.DefaultGenesisHashNetworkResolver(), asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	return &NodeContext{Context: ctx, ExportedAt: time.Now(), Path: "export/.appolicy/node.json", SourceTokens: tokens}
}

func tokenProblems(w *Workspace) []string {
	var out []string
	for _, p := range w.AllProblems() {
		if p.RuleID == policy.ConfigAdvisoryExternalTokenNotSet {
			out = append(out, string(p.Severity)+" "+p.Pointer)
		}
	}
	return out
}

// A workspace checked against an export that recorded the node's token names
// warns of each source a document takes a token for that its key had none
// of; it says nothing of tokens otherwise.
func TestWorkspaceWarnsOfTokensTheNodeLacked(t *testing.T) {
	w, err := Open(writeFile(t, t.TempDir(), "cosigner.json", fixture(t, externalFixture)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		node *NodeContext
		want string
	}{
		{"one of two set", roleNode(t, noderole.RoleCosigner, map[string][]string{tokenFixtureKey: {"treasury"}}),
			"warning /external_sources/screening/token"},
		// The default's tokens are the default's; the key has its own.
		{"set for the default only", roleNode(t, noderole.RoleCosigner, map[string][]string{policy.DefaultKey: {"screening", "treasury"}}),
			"warning /external_sources/screening/token,warning /external_sources/treasury/token"},
		{"every one set", roleNode(t, noderole.RoleCosigner, map[string][]string{tokenFixtureKey: {"screening", "treasury"}}), ""},
		{"no names recorded", roleNode(t, noderole.RoleCosigner, nil), ""},
		{"no node context", nil, ""},
		// A signer export does not govern a cosigner document.
		{"another role's export", roleNode(t, noderole.RoleSigner, map[string][]string{}), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Join(tokenProblems(w.WithNode(tt.node)), ","); got != tt.want {
				t.Fatalf("token problems = %q, want %q", got, tt.want)
			}
		})
	}
}
