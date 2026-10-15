// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyreview"
)

// On a cosigner node, e on a key that follows the default offers the
// presets; choosing one opens the editor on the preset under the key's name
// without asking the daemon for anything, and the edit is new for the key.
func TestPolicyPresetPickOpensPresetForKeyOnTheDefault(t *testing.T) {
	m := cosignerPoliciesModel("default")
	m.width, m.height = 120, 40
	m = selectKeyA(t, m)
	m, cmd := pressPolicyKey(t, m, "e")
	if m.viewState != ViewPolicyPresetPick || cmd != nil {
		t.Fatalf("e on a cosigner key on the default: view %v cmd %v, want the picker", m.viewState, cmd)
	}
	rendered := stripANSI(m.renderPolicyPresetPick())
	presets := policyreview.Presets(noderole.RoleCosigner)
	for _, want := range append([]string{"Start from the node default", "key " + policyViewKeyA}, presets[0].Name, presets[len(presets)-1].Name) {
		if !strings.Contains(rendered, want) {
			t.Fatalf("picker missing %q:\n%s", want, rendered)
		}
	}
	index := -1
	for i, p := range presets {
		if p.Name == "self-only" {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("no self-only preset")
	}
	for i := 0; i <= index; i++ {
		m, _ = pressPolicyKey(t, m, "down")
	}
	m, cmd = pressPolicyKey(t, m, "enter")
	edit := m.policies.apply.edit
	if m.viewState != ViewPolicyEdit || edit.loading || cmd != nil || edit.key != policyViewKeyA || !edit.isNew {
		t.Fatalf("enter on self-only: view %v edit key %q loading %v isNew %v cmd %v", m.viewState, edit.key, edit.loading, edit.isNew, cmd)
	}
	want, err := policyreview.PresetTemplate(noderole.RoleCosigner, "self-only", policyViewKeyA)
	if err != nil {
		t.Fatal(err)
	}
	if !policyTextEquivalent(want, policyEditText(m)) || !strings.Contains(policyEditText(m), fmt.Sprintf("%q preset", "self-only")) {
		t.Fatalf("editor text is not the self-only preset under key A:\n%s", policyEditText(m))
	}
	// The hint names the preset; it must not claim the text is the node default.
	rendered = stripANSI(m.renderPolicyEdit())
	if edit.preset != "self-only" || !strings.Contains(rendered, `Started from the "self-only" preset`) || strings.Contains(rendered, "node default") {
		t.Fatalf("editor hint for a preset (preset %q):\n%s", edit.preset, rendered)
	}
}

// The first choice is what e opened before presets existed: for a key on the
// default, the node default with the key filled in, fetched from the daemon.
func TestPolicyPresetPickFirstChoiceKeepsTheOldPath(t *testing.T) {
	m := cosignerPoliciesModel("default")
	m = selectKeyA(t, m)
	m, _ = pressPolicyKey(t, m, "e")
	m, _ = pressPolicyKey(t, m, "up")
	m, cmd := pressPolicyKey(t, m, "enter")
	edit := m.policies.apply.edit
	if m.viewState != ViewPolicyEdit || !edit.loading || edit.templateFor != policyViewKeyA || cmd == nil {
		t.Fatalf("first choice: view %v edit %+v cmd %v, want the default requested", m.viewState, edit, cmd)
	}
}

// The node default also offers the presets, with "Edit the current policy"
// first; esc goes back to the list with nothing changed.
func TestPolicyPresetPickForTheDefaultAndEsc(t *testing.T) {
	m := cosignerPoliciesModel("default")
	m, _ = pressPolicyKey(t, m, "e")
	if m.viewState != ViewPolicyPresetPick || m.policies.presetPick.row.key != policy.DefaultKey {
		t.Fatalf("e on the default: view %v pick %+v", m.viewState, m.policies.presetPick)
	}
	if rendered := stripANSI(m.renderPolicyPresetPick()); !strings.Contains(rendered, "Edit the current policy") || !strings.Contains(rendered, "the node default") {
		t.Fatalf("picker for the default:\n%s", rendered)
	}
	m, _ = pressPolicyKey(t, m, "esc")
	if m.viewState != ViewPolicies || m.policies.apply.edit.active {
		t.Fatalf("esc: view %v edit %+v", m.viewState, m.policies.apply.edit)
	}
}

// A key with a policy of its own, and every row on a signer node, open the
// editor directly: there are no presets to offer.
func TestPolicyPresetPickSkippedForOwnPolicyAndSigner(t *testing.T) {
	m := cosignerPoliciesModel("own", protocol.PolicyDocumentInfoWire{Key: policyViewKeyA, SHA256: "abc", Size: 10})
	m = selectKeyA(t, m)
	if m, _ = pressPolicyKey(t, m, "e"); m.viewState != ViewPolicyEdit {
		t.Fatalf("e on a key with its own policy: view %v, want the editor", m.viewState)
	}
	signer := loadedPoliciesModel(protocol.PolicyMessage{Success: true, NodeRole: "signer",
		Documents: []protocol.PolicyDocumentInfoWire{defaultDocInfo}, PolicySetSHA256: "set-digest"})
	if signer, _ = pressPolicyKey(t, signer, "e"); signer.viewState != ViewPolicyEdit {
		t.Fatalf("e on a signer default: view %v, want the editor", signer.viewState)
	}
}
