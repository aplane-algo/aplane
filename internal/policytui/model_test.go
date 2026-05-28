// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
)

func TestModelCyclesBoolFieldAndTracksModified(t *testing.T) {
	m := New(&fakeStore{}, &policy.StoredConfig{}, "/tmp/aplane", "default")

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	if cmd != nil {
		t.Fatal("space on bool field returned unexpected command")
	}
	got := updated.(Model)
	if got.policy.RejectForeignRekey == nil || *got.policy.RejectForeignRekey {
		t.Fatalf("RejectForeignRekey = %v, want false", got.policy.RejectForeignRekey)
	}
	if !got.modified() {
		t.Fatal("model should be modified after cycling bool")
	}

	updated, _ = got.Update(tea.KeyMsg{Type: tea.KeySpace})
	got = updated.(Model)
	if got.policy.RejectForeignRekey != nil {
		t.Fatalf("RejectForeignRekey = %v, want default true", got.policy.RejectForeignRekey)
	}
	if got.modified() {
		t.Fatal("model should be clean after cycling back to default true")
	}
}

func TestModelApplyUsesStoreAndClearsModified(t *testing.T) {
	store := &fakeStore{}
	m := New(store, &policy.StoredConfig{}, "/tmp/aplane", "default")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)

	updated, cmd := m.Update(keyRunes("a"))
	if cmd == nil {
		t.Fatal("apply returned nil command")
	}
	m = updated.(Model)
	if !m.busy {
		t.Fatal("model should be busy while apply command is running")
	}
	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(Model)

	if store.saves != 1 {
		t.Fatalf("saves = %d, want 1", store.saves)
	}
	if m.err != "" {
		t.Fatalf("err = %q, want empty", m.err)
	}
	if m.modified() {
		t.Fatal("model should be clean after successful apply")
	}
}

func TestModelApplyPromptsForMissingStorePassphrase(t *testing.T) {
	store := &passphraseFakeStore{}
	m := New(store, &policy.StoredConfig{}, "/tmp/aplane", "default")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)

	updated, cmd := m.Update(keyRunes("a"))
	if cmd != nil {
		t.Fatal("apply without passphrase returned command before prompt")
	}
	m = updated.(Model)
	if m.screen != screenApplyPassphrase {
		t.Fatalf("screen = %v, want passphrase prompt", m.screen)
	}
	if !strings.Contains(m.View(), "Enter the signer store passphrase") {
		t.Fatalf("passphrase prompt missing from view:\n%s", m.View())
	}

	updated, _ = m.Update(keyRunes("secret"))
	m = updated.(Model)
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("passphrase submit returned nil apply command")
	}
	m = updated.(Model)
	if !m.busy {
		t.Fatal("model should be busy after passphrase submit")
	}
	if string(store.passphrase) != "secret" {
		t.Fatalf("stored passphrase = %q, want secret", string(store.passphrase))
	}

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(Model)
	if store.saves != 1 {
		t.Fatalf("saves = %d, want 1", store.saves)
	}
	if m.err != "" {
		t.Fatalf("err = %q, want empty", m.err)
	}
	if m.modified() {
		t.Fatal("model should be clean after successful apply")
	}
}

func TestModelApplyFailureClearsPromptedPassphrase(t *testing.T) {
	store := &passphraseFakeStore{fakeStore: fakeStore{saveErr: errors.New("bad passphrase")}}
	m := New(store, &policy.StoredConfig{}, "/tmp/aplane", "default")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)

	updated, _ = m.Update(keyRunes("a"))
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("wrong"))
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("passphrase submit returned nil apply command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if m.err == "" {
		t.Fatal("err = empty, want apply failure")
	}
	if store.HasPassphrase() {
		t.Fatal("prompted passphrase remained cached after apply failure")
	}
}

func TestModifiedQuitRequiresConfirmation(t *testing.T) {
	m := New(&fakeStore{}, &policy.StoredConfig{}, "/tmp/aplane", "default")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)

	updated, cmd := m.Update(keyRunes("q"))
	if cmd != nil {
		t.Fatal("modified quit returned quit command without confirmation")
	}
	m = updated.(Model)
	if m.screen != screenQuitConfirm {
		t.Fatalf("screen = %v, want quit confirm", m.screen)
	}

	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd != nil {
		t.Fatal("cancel modified quit returned command")
	}
	m = updated.(Model)
	if m.screen != screenHome {
		t.Fatalf("screen = %v, want home after cancel", m.screen)
	}

	updated, cmd = m.Update(keyRunes("q"))
	if cmd != nil {
		t.Fatal("second modified quit returned quit command before confirmation")
	}
	_, cmd = updated.(Model).Update(keyRunes("q"))
	if cmd == nil {
		t.Fatal("confirmed discard quit returned nil command")
	}
}

func TestModifiedQuitCanApplyAndQuit(t *testing.T) {
	store := &fakeStore{}
	m := New(store, &policy.StoredConfig{}, "/tmp/aplane", "default")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("q"))
	m = updated.(Model)

	updated, cmd := m.Update(keyRunes("a"))
	if cmd == nil {
		t.Fatal("apply+quit returned nil apply command")
	}
	m = updated.(Model)
	if !m.quitAfterApply {
		t.Fatal("quitAfterApply = false, want true")
	}
	msg := cmd()
	_, quitCmd := m.Update(msg)
	if quitCmd == nil {
		t.Fatal("successful apply+quit returned nil quit command")
	}
	if store.saves != 1 {
		t.Fatalf("saves = %d, want 1", store.saves)
	}
}

func TestModelValidateReportsStoreError(t *testing.T) {
	store := &fakeStore{validateErr: errors.New("invalid policy")}
	m := New(store, &policy.StoredConfig{}, "/tmp/aplane", "default")

	updated, cmd := m.Update(keyRunes("v"))
	if cmd == nil {
		t.Fatal("validate returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if !strings.Contains(m.err, "invalid policy") {
		t.Fatalf("err = %q, want validation error", m.err)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestViewShowsTransferPolicySummary(t *testing.T) {
	enabled := true
	onNoRoute := "reject"
	m := New(&fakeStore{}, &policy.StoredConfig{
		TransferPolicy: &policy.StoredTransferPolicy{
			Enabled:   &enabled,
			OnNoRoute: &onNoRoute,
			Routes: []policy.StoredTransferRoute{
				{ID: "route_one"},
			},
		},
	}, "/tmp/aplane", "default")

	view := m.View()
	if !strings.Contains(view, "enabled=true routes=1") {
		t.Fatalf("View() missing transfer summary:\n%s", view)
	}
}

func TestHomeViewDoesNotShowFloatingFieldDescription(t *testing.T) {
	m := New(&fakeStore{}, &policy.StoredConfig{}, "/tmp/aplane", "default")

	view := m.View()
	if strings.Contains(view, "Reject rekey-to addresses outside the signer identity.") {
		t.Fatalf("home view includes floating field description:\n%s", view)
	}
}

func TestHomeViewShowsEffectivePolicyDefaults(t *testing.T) {
	m := New(&fakeStore{}, &policy.StoredConfig{}, "/tmp/aplane", "default")

	view := m.View()
	assertHomeSourceColumnAligned(t, view)
	for _, want := range []struct {
		label  string
		value  string
		source string
	}{
		{label: "Reject foreign rekey", value: "true", source: "default"},
		{label: "Reject close remainder", value: "false", source: "default"},
		{label: "Reject asset close", value: "false", source: "default"},
		{label: "Reject clawback", value: "false", source: "default"},
		{label: "Always review warnings", value: "false", source: "default"},
		{label: "Auto-approve self no-op transfer", value: "false", source: "default"},
		{label: "Max fee microAlgos", value: "0 (no limit)", source: "default"},
		{label: "Transfer routing", value: "enabled=false routes=0", source: "absent"},
	} {
		if !viewHasFieldValueSource(view, want.label, want.value, want.source) {
			t.Fatalf("home view missing %q = %q source %q:\n%s", want.label, want.value, want.source, view)
		}
	}
	if strings.Contains(view, "inherit") {
		t.Fatalf("home view includes inherit:\n%s", view)
	}
}

func TestHomeViewShowsExplicitPolicySources(t *testing.T) {
	rejectForeignRekey := false
	maxFee := uint64(2000)
	enabled := false
	onNoRoute := "operator_default"
	m := New(&fakeStore{}, &policy.StoredConfig{
		RejectForeignRekey: &rejectForeignRekey,
		MaxFeeMicroAlgos:   &maxFee,
		TransferPolicy: &policy.StoredTransferPolicy{
			SchemaVersion: 1,
			Enabled:       &enabled,
			OnNoRoute:     &onNoRoute,
		},
	}, "/tmp/aplane", "default")

	view := m.View()
	assertHomeSourceColumnAligned(t, view)
	for _, want := range []struct {
		label  string
		value  string
		source string
	}{
		{label: "Reject foreign rekey", value: "false", source: "explicit"},
		{label: "Max fee microAlgos", value: "2000", source: "explicit"},
		{label: "Transfer routing", value: "enabled=false routes=0", source: "explicit"},
	} {
		if !viewHasFieldValueSource(view, want.label, want.value, want.source) {
			t.Fatalf("home view missing %q = %q source %q:\n%s", want.label, want.value, want.source, view)
		}
	}
}

func TestRouteScreenCyclesSelectedRouteEnabled(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("enter on transfer policy returned unexpected command")
	}
	got := updated.(Model)
	if got.screen != screenRoutes {
		t.Fatalf("screen = %v, want routes", got.screen)
	}

	updated, _ = got.Update(tea.KeyMsg{Type: tea.KeySpace})
	got = updated.(Model)
	if got.policy.TransferPolicy.Routes[0].Enabled == nil || *got.policy.TransferPolicy.Routes[0].Enabled {
		t.Fatalf("route enabled = %v, want false", got.policy.TransferPolicy.Routes[0].Enabled)
	}
	if !got.modified() {
		t.Fatal("model should be modified after route enabled edit")
	}

	updated, _ = got.Update(tea.KeyMsg{Type: tea.KeySpace})
	got = updated.(Model)
	if got.policy.TransferPolicy.Routes[0].Enabled != nil {
		t.Fatalf("route enabled = %v, want default true", got.policy.TransferPolicy.Routes[0].Enabled)
	}
	if got.modified() {
		t.Fatal("model should be clean after cycling route enabled back to default true")
	}
}

func TestRouteScreenShowsBlockedDestinations(t *testing.T) {
	stored := routePolicy()
	stored.TransferPolicy.BlockedDestinations = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	view := m.View()
	if !strings.Contains(view, "Blocked Destinations") ||
		!strings.Contains(view, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ") {
		t.Fatalf("route view missing blocked destinations:\n%s", view)
	}
}

func TestRouteScreenEditsBlockedDestinations(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("b"))
	m = updated.(Model)
	if m.screen != screenBlockedDestinationsEdit {
		t.Fatalf("screen = %v, want blocked destinations editor", m.screen)
	}

	updated, _ = m.Update(keyRunes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"))
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Fatal("esc on blocked destinations editor returned nil auto-save command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if m.screen != screenRoutes {
		t.Fatalf("screen = %v, want routes after apply", m.screen)
	}
	if got := m.policy.TransferPolicy.BlockedDestinations; len(got) != 1 || got[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
		t.Fatalf("blocked destinations = %+v, want typed address", got)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestBlockedDestinationsEditorInitializesRoutingSafely(t *testing.T) {
	store := &fakeStore{}
	m := New(store, &policy.StoredConfig{}, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("b"))
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"))
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Fatal("esc on blocked destinations editor returned nil auto-save command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if m.policy.TransferPolicy == nil {
		t.Fatal("TransferPolicy = nil, want initialized")
	}
	if m.policy.TransferPolicy.Enabled == nil || !*m.policy.TransferPolicy.Enabled {
		t.Fatalf("enabled = %v, want true", m.policy.TransferPolicy.Enabled)
	}
	if m.policy.TransferPolicy.OnNoRoute == nil || *m.policy.TransferPolicy.OnNoRoute != string(policy.TransferOnNoRouteOperatorDefault) {
		t.Fatalf("on_no_route = %v, want operator_default", m.policy.TransferPolicy.OnNoRoute)
	}
	if !m.policy.TransferPolicy.RoutesSet {
		t.Fatal("RoutesSet = false, want explicit empty route list")
	}
}

func TestRouteScreenShowsRouteDescriptionInline(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	view := m.routeView()

	if !strings.Contains(view, "treasury - Treasury payments") {
		t.Fatalf("guard view missing inline route description:\n%s", view)
	}
	if got := strings.Count(view, "Treasury payments"); got != 1 {
		t.Fatalf("route description rendered %d times, want once:\n%s", got, view)
	}
	for _, want := range []string{"Transfer Guards", "net=mainnet", "src=*", "dst=self", "asset=algo"} {
		if !strings.Contains(view, want) {
			t.Fatalf("guard view missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "enabled=") || strings.Contains(view, "networks=") ||
		strings.Contains(view, "assets=") || strings.Contains(view, "destinations=") {
		t.Fatalf("guard view includes legacy metadata columns:\n%s", view)
	}
}

func TestRouteScreenShowsTransferPolicyYAML(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("y"))
	m = updated.(Model)

	if m.screen != screenRouteYAML {
		t.Fatalf("screen = %v, want route YAML", m.screen)
	}
	view := m.View()
	for _, want := range []string{
		"Transfer Policy YAML",
		"transfer_policy:",
		"routes:",
		"id: treasury_algo",
		"description: Treasury payments",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("YAML view missing %q:\n%s", want, view)
		}
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.screen != screenRoutes {
		t.Fatalf("screen after esc = %v, want routes", m.screen)
	}
}

func TestAssetSetScreenShowsStoredSets(t *testing.T) {
	stored := routePolicy()
	stored.TransferPolicy.AssetSets = map[string]policy.StoredAssetSet{
		"usdc": {
			"mainnet": []uint64{31566704},
			"testnet": []uint64{10458941},
		},
	}
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("t"))
	m = updated.(Model)

	if m.screen != screenAssetSets {
		t.Fatalf("screen = %v, want asset sets", m.screen)
	}
	view := m.View()
	for _, want := range []string{
		"Asset Sets",
		"usdc",
		"networks=2",
		"assets=2",
		"mainnet:31566704",
		"testnet:10458941",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("asset set view missing %q:\n%s", want, view)
		}
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.screen != screenRoutes {
		t.Fatalf("screen after esc = %v, want routes", m.screen)
	}
}

func TestAssetSetEditorEditsASAIDsAsText(t *testing.T) {
	stored := routePolicy()
	stored.TransferPolicy.AssetSets = map[string]policy.StoredAssetSet{
		"usdc": {
			"mainnet": []uint64{31566704},
		},
	}
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("t"))
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if m.screen != screenAssetSetEdit {
		t.Fatalf("screen = %v, want asset set edit", m.screen)
	}
	view := m.assetSetEditView()
	for _, want := range []string{"Edit Asset Set", "Name", "usdc", "mainnet"} {
		if !strings.Contains(view, want) {
			t.Fatalf("asset set edit view missing %q:\n%s", want, view)
		}
	}

	m.editCursor = 2 // ASA IDs for first network row.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenAssetSetTextEdit {
		t.Fatalf("screen = %v, want asset set text edit", m.screen)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("31566704,31566705"))
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)

	if m.screen != screenAssetSetEdit {
		t.Fatalf("screen after esc = %v, want asset set edit", m.screen)
	}
	if got := parseCSV(m.editAssetSetRows[0].ASAIDs); strings.Join(got, ",") != "31566704,31566705" {
		t.Fatalf("ASA IDs = %#v, want edited list", got)
	}
	if got := assetSetEditDisplayValue("asa_ids", m.editAssetSetRows[0].ASAIDs); got != "31566704,31566705" {
		t.Fatalf("ASA IDs display = %q, want text value", got)
	}
}

func TestAssetSetEditAppliesValidatedSet(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.AssetSets = map[string]policy.StoredAssetSet{
		"usdc": {
			"testnet": []uint64{10458941},
		},
	}
	m := New(store, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("t"))
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	m.editAssetSetName = "stablecoins"
	m.editAssetSetRows[0].ASAIDs = "10458941,999"
	updated, cmd := m.applyAssetSetEdit()
	if cmd == nil {
		t.Fatal("applyAssetSetEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if m.screen != screenAssetSetEdit {
		t.Fatalf("screen = %v, want asset set edit after save", m.screen)
	}
	if _, ok := m.policy.TransferPolicy.AssetSets["usdc"]; ok {
		t.Fatal("old asset set name still exists after rename")
	}
	got := m.policy.TransferPolicy.AssetSets["stablecoins"]
	if got == nil {
		t.Fatal("renamed asset set missing")
	}
	if ids := got["testnet"]; len(ids) != 2 || ids[0] != 999 || ids[1] != 10458941 {
		t.Fatalf("testnet ids = %#v, want sorted ids", ids)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestAssetSetEditEscDuringValidationDiscardsLateResult(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.AssetSets = map[string]policy.StoredAssetSet{
		"usdc": {
			"testnet": []uint64{10458941},
		},
	}
	m := New(store, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("t"))
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	m.editAssetSetName = "stablecoins"

	updated, cmd := m.applyAssetSetEdit()
	if cmd == nil {
		t.Fatal("applyAssetSetEdit() returned nil command")
	}
	m = updated.(Model)
	if !m.busy {
		t.Fatal("model should be busy while asset set validation is running")
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.busy {
		t.Fatal("model stayed busy after discarding asset set edit")
	}
	if m.screen != screenAssetSets {
		t.Fatalf("screen = %v, want asset sets after discard", m.screen)
	}

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(Model)
	if _, ok := m.policy.TransferPolicy.AssetSets["stablecoins"]; ok {
		t.Fatal("late asset set apply changed policy after discard")
	}
	if _, ok := m.policy.TransferPolicy.AssetSets["usdc"]; !ok {
		t.Fatal("original asset set missing after discarded apply")
	}
}

func TestAssetSetScreenNewCloneAndDelete(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.AssetSets = map[string]policy.StoredAssetSet{
		"usdc": {
			"testnet": []uint64{10458941},
		},
	}
	m := New(store, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("t"))
	m = updated.(Model)

	updated, _ = m.Update(keyRunes("c"))
	m = updated.(Model)
	if m.screen != screenAssetSetEdit {
		t.Fatalf("screen after clone = %v, want asset set edit", m.screen)
	}
	if m.editAssetSetName != "usdc_copy" {
		t.Fatalf("clone name = %q, want usdc_copy", m.editAssetSetName)
	}
	updated, cmd := m.applyAssetSetEdit()
	if cmd == nil {
		t.Fatal("clone apply returned nil command")
	}
	updated, _ = updated.(Model).Update(cmd())
	m = updated.(Model)
	if _, ok := m.policy.TransferPolicy.AssetSets["usdc_copy"]; !ok {
		t.Fatal("cloned asset set missing after apply")
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.screen != screenAssetSets {
		t.Fatalf("screen after esc = %v, want asset sets", m.screen)
	}
	updated, _ = m.Update(keyRunes("d"))
	m = updated.(Model)
	if m.screen != screenDeleteAssetSetConfirm {
		t.Fatalf("screen = %v, want delete confirm", m.screen)
	}
	updated, cmd = m.Update(keyRunes("y"))
	if cmd == nil {
		t.Fatal("delete confirm returned nil command")
	}
	updated, _ = updated.(Model).Update(cmd())
	m = updated.(Model)
	if _, ok := m.policy.TransferPolicy.AssetSets["usdc_copy"]; ok {
		t.Fatal("deleted asset set still exists")
	}
	if store.validations != 2 {
		t.Fatalf("validations = %d, want 2", store.validations)
	}

	updated, _ = m.Update(keyRunes("n"))
	m = updated.(Model)
	if m.screen != screenAssetSetEdit {
		t.Fatalf("screen after new = %v, want asset set edit", m.screen)
	}
	if m.editAssetSetName != "asset_set" {
		t.Fatalf("new name = %q, want asset_set", m.editAssetSetName)
	}
}

func TestAssetSetScreenSeedsUSDCWhenMissing(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("t"))
	m = updated.(Model)

	if m.screen != screenAssetSets {
		t.Fatalf("screen = %v, want asset sets", m.screen)
	}
	if !m.modified() {
		t.Fatal("model should be modified after seeding default USDC set")
	}
	view := m.assetSetView()
	if !strings.Contains(view, "usdc") {
		t.Fatalf("asset set view missing seeded usdc:\n%s", view)
	}
	set := m.policy.TransferPolicy.AssetSets["usdc"]
	if got := joinUint64s(set["mainnet"]); got != "31566704" {
		t.Fatalf("mainnet USDC = %q, want 31566704", got)
	}
	if got := joinUint64s(set["testnet"]); got != "10458941" {
		t.Fatalf("testnet USDC = %q, want 10458941", got)
	}
}

func TestRouteYAMLViewPageKeysScrollByPage(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.screen = screenRouteYAML
	m.height = 12

	nextModel, _ := m.handleRouteYAMLKey(tea.KeyMsg{Type: tea.KeyPgDown})
	next := nextModel.(Model)
	if next.routeYAMLOffset != next.routeYAMLVisibleLines() {
		t.Fatalf("routeYAMLOffset after pgdown = %d, want %d",
			next.routeYAMLOffset, next.routeYAMLVisibleLines())
	}

	nextModel, _ = next.handleRouteYAMLKey(tea.KeyMsg{Type: tea.KeyPgUp})
	next = nextModel.(Model)
	if next.routeYAMLOffset != 0 {
		t.Fatalf("routeYAMLOffset after pgup = %d, want 0", next.routeYAMLOffset)
	}
}

func TestRouteYAMLViewConstrainsLongLines(t *testing.T) {
	stored := routePolicy()
	longDescription := strings.Repeat("long-description-", 12)
	stored.TransferPolicy.Routes[0].Description = longDescription
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")
	m.screen = screenRouteYAML
	m.width = 40

	view := m.routeYAMLView()
	if strings.Contains(view, longDescription) {
		t.Fatalf("YAML view contains unconstrained long line:\n%s", view)
	}
	if !strings.Contains(view, "...") {
		t.Fatalf("YAML view did not ellipsize long line:\n%s", view)
	}
}

func TestRouteYAMLViewFitsTerminalHeight(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.screen = screenRouteYAML
	m.width = 100
	m.height = 24

	view := m.View()
	if got := renderedLineCount(view); got > m.height {
		t.Fatalf("rendered YAML view height = %d, want <= %d\n%s", got, m.height, view)
	}
}

func TestRouteScreenCanApplyRouteEditsToProduction(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)

	updated, cmd := m.Update(keyRunes("a"))
	if cmd == nil {
		t.Fatal("apply returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if store.saves != 1 {
		t.Fatalf("saves = %d, want 1", store.saves)
	}
	if m.modified() {
		t.Fatal("model should be clean after applying route edit")
	}
}

func TestWriteFilePopupWritesDraftWithoutApplyingProduction(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)
	if !m.modified() {
		t.Fatal("model should be modified after policy edit")
	}

	updated, _ = m.Update(keyRunes("w"))
	m = updated.(Model)
	if m.screen != screenWriteFile {
		t.Fatalf("screen = %v, want write file popup", m.screen)
	}

	path := filepath.Join(t.TempDir(), "draft-policy.yaml")
	updated, _ = m.Update(keyRunes(path))
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("write returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if store.saves != 0 {
		t.Fatalf("saves = %d, want no production apply", store.saves)
	}
	if !m.modified() {
		t.Fatal("model should remain modified after writing a draft file")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(draft) error = %v", err)
	}
	want, err := marshalStored(m.policy)
	if err != nil {
		t.Fatalf("marshalStored() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("draft file bytes mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if _, err := os.Stat(path + ".hmac"); !os.IsNotExist(err) {
		t.Fatalf("draft sidecar stat error = %v, want missing sidecar", err)
	}

	updated, cmd = m.Update(keyRunes("q"))
	if cmd != nil {
		t.Fatal("modified quit after draft write returned quit command without confirmation")
	}
	m = updated.(Model)
	if m.screen != screenQuitConfirm {
		t.Fatalf("screen = %v, want quit confirm", m.screen)
	}
	view := m.View()
	if !strings.Contains(view, "Production Not Applied") {
		t.Fatalf("quit prompt missing production-apply wording:\n%s", view)
	}
	if strings.Contains(view, "Unsaved Changes") {
		t.Fatalf("quit prompt used misleading unsaved wording:\n%s", view)
	}
}

func TestRouteScreenNewRouteInitializesTransferPolicy(t *testing.T) {
	m := New(&fakeStore{}, &policy.StoredConfig{}, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	updated, _ = m.Update(keyRunes("n"))
	m = updated.(Model)

	if m.policy.TransferPolicy == nil {
		t.Fatal("TransferPolicy = nil, want initialized")
	}
	if m.policy.TransferPolicy.Enabled == nil || !*m.policy.TransferPolicy.Enabled {
		t.Fatalf("TransferPolicy.Enabled = %v, want true", m.policy.TransferPolicy.Enabled)
	}
	if m.policy.TransferPolicy.OnNoRoute == nil || *m.policy.TransferPolicy.OnNoRoute != "reject" {
		t.Fatalf("OnNoRoute = %v, want reject", m.policy.TransferPolicy.OnNoRoute)
	}
	if got := len(m.policy.TransferPolicy.Routes); got != 1 {
		t.Fatalf("routes = %d, want 1", got)
	}
	if route := m.policy.TransferPolicy.Routes[0]; route.ID != "new_guard_algo" {
		t.Fatalf("new guard route ID = %q, want new_guard_algo", route.ID)
	}
	usdc := m.policy.TransferPolicy.AssetSets["usdc"]
	if got := joinUint64s(usdc["mainnet"]); got != "31566704" {
		t.Fatalf("default mainnet USDC = %q, want 31566704", got)
	}
	if got := joinUint64s(usdc["testnet"]); got != "10458941" {
		t.Fatalf("default testnet USDC = %q, want 10458941", got)
	}
	if err := (&fakeStore{}).Validate(context.Background(), m.policy); err != nil {
		t.Fatalf("new route policy should validate via fake store: %v", err)
	}
}

func TestTransferSettingsOpenInitializesDisabledPolicy(t *testing.T) {
	m := New(&fakeStore{}, &policy.StoredConfig{}, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	updated, _ = m.Update(keyRunes("p"))
	m = updated.(Model)

	if m.policy.TransferPolicy == nil {
		t.Fatal("TransferPolicy = nil, want initialized")
	}
	if m.policy.TransferPolicy.Enabled == nil || *m.policy.TransferPolicy.Enabled {
		t.Fatalf("TransferPolicy.Enabled = %v, want false", m.policy.TransferPolicy.Enabled)
	}
	if got := len(m.policy.TransferPolicy.Routes); got != 0 {
		t.Fatalf("routes = %d, want 0", got)
	}
}

func TestRouteScreenNewRouteMarksRoutesSetOnExistingTransferPolicy(t *testing.T) {
	enabled := true
	onNoRoute := "reject"
	m := New(&fakeStore{}, &policy.StoredConfig{
		TransferPolicy: &policy.StoredTransferPolicy{
			SchemaVersion: 1,
			Enabled:       &enabled,
			OnNoRoute:     &onNoRoute,
		},
	}, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.policy.TransferPolicy.RoutesSet {
		t.Fatal("test setup unexpectedly has RoutesSet=true before adding a route")
	}

	updated, _ = m.Update(keyRunes("n"))
	m = updated.(Model)

	if !m.policy.TransferPolicy.RoutesSet {
		t.Fatal("RoutesSet = false after adding a route")
	}
}

func TestRouteScreenCloneDeleteAndReorder(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	updated, _ = m.Update(keyRunes("c"))
	m = updated.(Model)
	if got := len(m.policy.TransferPolicy.Routes); got != 2 {
		t.Fatalf("routes after clone = %d, want 2", got)
	}
	if got := m.policy.TransferPolicy.Routes[1].ID; got != "treasury_copy_algo" {
		t.Fatalf("clone ID = %q, want treasury_copy_algo", got)
	}
	if got := m.policy.TransferPolicy.Routes[1].Description; got != "" {
		t.Fatalf("clone description = %q, want empty", got)
	}

	updated, _ = m.Update(keyRunes("u"))
	m = updated.(Model)
	if got := m.policy.TransferPolicy.Routes[0].ID; got != "treasury_copy_algo" {
		t.Fatalf("first route after move up = %q, want clone", got)
	}

	updated, _ = m.Update(keyRunes("U"))
	m = updated.(Model)
	if got := m.policy.TransferPolicy.Routes[1].ID; got != "treasury_copy_algo" {
		t.Fatalf("second route after move down = %q, want clone", got)
	}

	updated, _ = m.Update(keyRunes("d"))
	m = updated.(Model)
	if m.screen != screenDeleteRouteConfirm {
		t.Fatalf("screen = %v, want delete confirmation", m.screen)
	}
	updated, _ = m.Update(keyRunes("y"))
	m = updated.(Model)
	if got := len(m.policy.TransferPolicy.Routes); got != 1 {
		t.Fatalf("routes after delete = %d, want 1", got)
	}
	if got := m.policy.TransferPolicy.Routes[0].ID; got != "treasury_algo" {
		t.Fatalf("remaining route = %q, want original", got)
	}
}

func TestRouteDeleteCanBeCanceled(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	updated, _ = m.Update(keyRunes("d"))
	m = updated.(Model)
	if m.screen != screenDeleteRouteConfirm {
		t.Fatalf("screen = %v, want delete confirmation", m.screen)
	}
	updated, _ = m.Update(keyRunes("n"))
	m = updated.(Model)
	if m.screen != screenRoutes {
		t.Fatalf("screen = %v, want routes after cancel", m.screen)
	}
	if got := len(m.policy.TransferPolicy.Routes); got != 1 {
		t.Fatalf("routes after cancel = %d, want 1", got)
	}
}

func TestRouteEditFormAppliesValidatedRoute(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want route edit", m.screen)
	}
	setEditField(&m, "networks", "mainnet,testnet")
	setEditAssetField(&m, 0, "review_above", "100")

	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want route edit after save", m.screen)
	}
	route := m.policy.TransferPolicy.Routes[0]
	if route.ID != "treasury_algo" {
		t.Fatalf("route ID = %q, want treasury_algo", route.ID)
	}
	if got := strings.Join(route.Networks, ","); got != "mainnet,testnet" {
		t.Fatalf("networks = %q, want mainnet,testnet", got)
	}
	if route.Limits == nil || route.Limits.ReviewAbove == nil || *route.Limits.ReviewAbove != 100_000_000 {
		t.Fatalf("review limit = %+v, want 100 ALGO in microAlgos", route.Limits)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestRouteEditFormEditsGuardNameAndDescription(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want route edit", m.screen)
	}

	m.editCursor = editFieldIndex(t, m, "id")
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("treasury_ops"))
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("route name edit returned nil auto-save command")
	}
	updated, _ = updated.(Model).Update(cmd())
	m = updated.(Model)

	m.editCursor = editFieldIndex(t, m, "description")
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("Operations"))
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("payments"))
	m = updated.(Model)
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("route description edit returned nil auto-save command")
	}
	updated, _ = updated.(Model).Update(cmd())
	m = updated.(Model)

	route := m.policy.TransferPolicy.Routes[0]
	if route.ID != "treasury_ops_algo" {
		t.Fatalf("route ID = %q, want treasury_ops_algo", route.ID)
	}
	if route.Description != "Operations payments" {
		t.Fatalf("route description = %q, want Operations payments", route.Description)
	}
	if store.validations != 2 {
		t.Fatalf("validations = %d, want 2", store.validations)
	}
}

func TestRouteEditFormWritesGuardNameAssetRouteIDs(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want route edit", m.screen)
	}

	setEditField(&m, "id", "test")
	setEditField(&m, "description", "Test guard")
	m.addEditAssetRow()
	setEditAssetField(&m, 1, "asset", "@usdc")

	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if len(m.policy.TransferPolicy.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(m.policy.TransferPolicy.Routes))
	}
	for i, want := range []struct {
		id    string
		asset string
	}{
		{id: "test_algo", asset: "algo"},
		{id: "test_usdc", asset: "@usdc"},
	} {
		route := m.policy.TransferPolicy.Routes[i]
		if route.ID != want.id {
			t.Fatalf("route %d ID = %q, want %s", i, route.ID, want.id)
		}
		if route.Description != "Test guard" {
			t.Fatalf("route %d description = %q, want Test guard", i, route.Description)
		}
		if got := joinAssetTerms(route.Assets); got != want.asset {
			t.Fatalf("route %d asset = %q, want %s", i, got, want.asset)
		}
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestRouteEditFormDisplaysAlgoThresholdsInAlgo(t *testing.T) {
	stored := routePolicy()
	stored.TransferPolicy.Routes[0].Limits = &policy.StoredAmountLimits{
		ReviewAbove: uint64Ptr(50_000_000),
		RejectAbove: uint64Ptr(75_500_000),
	}
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if got := editAssetFieldValue(m, 0, "review_above"); got != "50" {
		t.Fatalf("review_above display = %q, want 50", got)
	}
	if got := editAssetFieldValue(m, 0, "reject_above"); got != "75.5" {
		t.Fatalf("reject_above display = %q, want 75.5", got)
	}
}

func TestRouteEditFormParsesASADisplayThresholds(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.Routes[0].Networks = []string{"testnet"}
	stored.TransferPolicy.Routes[0].Assets = []policy.StoredAssetTerm{{Raw: "10458941"}}
	stored.TransferPolicy.Routes[0].Limits = &policy.StoredAmountLimits{
		ReviewAbove: uint64Ptr(5_000_000),
	}
	m := New(store, stored, t.TempDir(), "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if got := editAssetFieldValue(m, 0, "review_above"); got != "5" {
		t.Fatalf("review_above display = %q, want 5 USDC", got)
	}
	setEditAssetField(&m, 0, "reject_above", "7.5")
	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	limits := m.policy.TransferPolicy.Routes[0].Limits
	if limits == nil || limits.RejectAbove == nil || *limits.RejectAbove != 7_500_000 {
		t.Fatalf("reject limit = %+v, want 7.5 USDC in raw units", limits)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestRouteEditFormAppliesGroupedAssetRows(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.Routes = []policy.StoredTransferRoute{
		{
			ID:           "treasury_algo",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
			Destinations: []string{"self"},
			Limits:       &policy.StoredAmountLimits{RejectAbove: uint64Ptr(50_000_000)},
		},
		{
			ID:           "treasury_usdc",
			Networks:     []string{"testnet"},
			Sources:      []string{"*"},
			Assets:       []policy.StoredAssetTerm{{Raw: "10458941"}},
			Destinations: []string{"self"},
		},
	}
	m := New(store, stored, t.TempDir(), "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want grouped route edit", m.screen)
	}
	if got := len(m.editAssetRows); got != 2 {
		t.Fatalf("edit asset rows = %d, want 2", got)
	}
	setEditField(&m, "sources", "@ops")
	setEditAssetField(&m, 1, "asset", "*")
	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if len(m.policy.TransferPolicy.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(m.policy.TransferPolicy.Routes))
	}
	if got := strings.Join(m.policy.TransferPolicy.Routes[0].Sources, ","); got != "@ops" {
		t.Fatalf("route 0 sources = %q, want @ops", got)
	}
	if got := joinAssetTerms(m.policy.TransferPolicy.Routes[1].Assets); got != "*" {
		t.Fatalf("route 1 assets = %q, want *", got)
	}
	if m.policy.TransferPolicy.Routes[0].Limits == nil ||
		m.policy.TransferPolicy.Routes[0].Limits.RejectAbove == nil ||
		*m.policy.TransferPolicy.Routes[0].Limits.RejectAbove != 50_000_000 {
		t.Fatalf("route 0 limits = %+v, want preserved ALGO reject threshold", m.policy.TransferPolicy.Routes[0].Limits)
	}
}

func TestRouteEditFormEditsAssetSetThresholdsAcrossNetworks(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.AssetSets = map[string]policy.StoredAssetSet{
		"usdc": {
			"mainnet": []uint64{31566704},
			"testnet": []uint64{10458941},
		},
	}
	stored.TransferPolicy.Routes[0].Networks = []string{"mainnet", "testnet"}
	stored.TransferPolicy.Routes[0].Assets = []policy.StoredAssetTerm{{Raw: "@usdc"}}
	stored.TransferPolicy.Routes[0].LimitsByNetwork = map[string]policy.StoredAmountLimits{
		"mainnet": {RejectAbove: uint64Ptr(5_000_000)},
		"testnet": {RejectAbove: uint64Ptr(5_000_000)},
	}
	m := New(store, stored, t.TempDir(), "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want route edit", m.screen)
	}
	if got := editAssetFieldValue(m, 0, "reject_above"); got != "5" {
		t.Fatalf("reject_above display = %q, want 5 USDC", got)
	}
	setEditAssetField(&m, 0, "reject_above", "7.5")
	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	route := m.policy.TransferPolicy.Routes[0]
	if route.Limits != nil {
		t.Fatalf("Limits = %+v, want nil for multi-network asset set", route.Limits)
	}
	for _, network := range []string{"mainnet", "testnet"} {
		limits := route.LimitsByNetwork[network]
		if limits.RejectAbove == nil || *limits.RejectAbove != 7_500_000 {
			t.Fatalf("%s reject = %+v, want 7500000", network, limits.RejectAbove)
		}
	}
}

func TestRouteEditFormResolvesCachedASASymbolToID(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.Routes[0].Networks = []string{"testnet"}
	stored.TransferPolicy.Routes[0].Assets = []policy.StoredAssetTerm{{Raw: "algo"}}
	m := New(store, stored, t.TempDir(), "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	setEditAssetField(&m, 0, "asset", "USDC")
	setEditAssetField(&m, 0, "review_above", "0.5")
	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	route := m.policy.TransferPolicy.Routes[0]
	if len(route.Assets) != 1 || route.Assets[0].Raw != "10458941" {
		t.Fatalf("assets = %+v, want testnet USDC asset ID", route.Assets)
	}
	if route.Limits == nil || route.Limits.ReviewAbove == nil || *route.Limits.ReviewAbove != 500_000 {
		t.Fatalf("review limit = %+v, want 0.5 USDC in raw units", route.Limits)
	}
}

func TestRouteEditFormAcceptsBareAssetSetName(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.AssetSets = map[string]policy.StoredAssetSet{
		"usdc": {
			"testnet": []uint64{10458941},
		},
	}
	stored.TransferPolicy.Routes[0].Networks = []string{"testnet"}
	m := New(store, stored, t.TempDir(), "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	setEditAssetField(&m, 0, "asset", "usdc")
	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)
	route := m.policy.TransferPolicy.Routes[0]
	if len(route.Assets) != 1 || route.Assets[0].Raw != "@usdc" {
		t.Fatalf("assets = %+v, want @usdc", route.Assets)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestRouteAssetHintListsDefinedAssetSets(t *testing.T) {
	stored := routePolicy()
	stored.TransferPolicy.AssetSets = map[string]policy.StoredAssetSet{
		"usdc": {"testnet": []uint64{10458941}},
	}
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")

	hint := m.routeTextHint("asset")
	if !strings.Contains(hint, "usdc") {
		t.Fatalf("asset hint = %q, want defined asset set", hint)
	}
	if strings.Contains(hint, "@usdc") {
		t.Fatalf("asset hint = %q, should show bare asset set name", hint)
	}
}

func TestRouteEditFormShowsCountsForSourcesAndDestinations(t *testing.T) {
	stored := routePolicy()
	stored.TransferPolicy.Routes[0].Sources = []string{
		"SOURCEONEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"SOURCETWOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	stored.TransferPolicy.Routes[0].Destinations = []string{"self", "@ops", "*"}
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if got := routeEditFieldDisplayValue(editFieldByKey(t, m, "sources")); got != "2" {
		t.Fatalf("sources display value = %q, want 2", got)
	}
	if got := routeEditFieldDisplayValue(editFieldByKey(t, m, "destinations")); got != "3" {
		t.Fatalf("destinations display value = %q, want 3", got)
	}
	view := m.routeEditView()
	if strings.Contains(view, "SOURCEONE") || strings.Contains(view, "@ops") {
		t.Fatalf("route edit view leaked full address-list contents:\n%s", view)
	}
}

func TestRouteEditFormShowsSingleListValue(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if got := routeEditFieldDisplayValue(editFieldByKey(t, m, "networks")); got != "mainnet" {
		t.Fatalf("networks display value = %q, want mainnet", got)
	}
	if got := routeEditFieldDisplayValue(editFieldByKey(t, m, "sources")); got != "*" {
		t.Fatalf("sources display value = %q, want *", got)
	}
	if got := routeEditFieldDisplayValue(editFieldByKey(t, m, "destinations")); got != "self" {
		t.Fatalf("destinations display value = %q, want self", got)
	}
}

func TestRouteEditSourcesOpenListEditor(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	m.editCursor = editFieldIndex(t, m, "sources")

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("enter on sources returned unexpected command")
	}
	m = updated.(Model)
	if m.screen != screenRouteListEdit {
		t.Fatalf("screen = %v, want address-list editor", m.screen)
	}

	updated, _ = m.Update(keyRunes("@treasury,"))
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("@ops"))
	m = updated.(Model)
	if got := parseCSV(editFieldByKey(t, m, "sources").value); strings.Join(got, ",") != "*,@treasury,@ops" {
		t.Fatalf("sources value = %#v, want existing source plus two added terms", got)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.screen != screenRouteEdit {
		t.Fatalf("screen after esc = %v, want route edit", m.screen)
	}
	if got := routeEditFieldDisplayValue(editFieldByKey(t, m, "sources")); got != "3" {
		t.Fatalf("sources display value after edit = %q, want 3", got)
	}
}

func TestRouteEditDestinationOpensListEditor(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	m.editCursor = editFieldIndex(t, m, "destinations")

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenRouteListEdit {
		t.Fatalf("screen = %v, want list editor", m.screen)
	}
	updated, _ = m.Update(keyRunes("@ops"))
	m = updated.(Model)
	if got := parseCSV(editFieldByKey(t, m, "destinations").value); strings.Join(got, ",") != "self,@ops" {
		t.Fatalf("destinations value = %#v, want existing self plus typed term", got)
	}
}

func TestRouteEditTextFieldUsesPopupEditor(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	m.editCursor = len(m.editFields) // Asset

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenRouteTextEdit {
		t.Fatalf("screen = %v, want text editor", m.screen)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("10458941"))
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if m.screen != screenRouteEdit {
		t.Fatalf("screen after enter = %v, want route edit", m.screen)
	}
	if got := m.editAssetRows[0].asset; got != "10458941" {
		t.Fatalf("asset field = %q, want 10458941", got)
	}
}

func TestRouteEditChoiceFieldUsesPopupEditor(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	m.editCursor = editFieldIndex(t, m, "enabled")

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenRouteChoiceEdit {
		t.Fatalf("screen = %v, want choice editor", m.screen)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if m.screen != screenRouteEdit {
		t.Fatalf("screen after select = %v, want route edit", m.screen)
	}
	if got := editFieldByKey(t, m, "enabled").value; got != "false" {
		t.Fatalf("enabled field = %q, want false", got)
	}
}

func TestRouteEditFieldAutoSavesDraft(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	m.editCursor = len(m.editFields) + 2

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenRouteTextEdit {
		t.Fatalf("screen = %v, want route text edit", m.screen)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("50"))
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("route field close returned nil auto-save command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want route edit after auto-save", m.screen)
	}
	if got := m.policy.TransferPolicy.Routes[0].Limits.RejectAbove; got == nil || *got != 50_000_000 {
		t.Fatalf("reject_above = %v, want 50000000", got)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestRouteEditFormEscDuringValidationDiscardsLateResult(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	setEditField(&m, "enabled", "true")

	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	m = updated.(Model)
	if !m.busy {
		t.Fatal("model should be busy while route validation is running")
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.busy {
		t.Fatal("model stayed busy after discarding route edit")
	}
	if m.screen != screenRoutes {
		t.Fatalf("screen = %v, want routes after discard", m.screen)
	}

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(Model)
	if got := m.policy.TransferPolicy.Routes[0].Enabled; got != nil {
		t.Fatalf("late route apply changed enabled to %v", got)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestRouteEditFormLeavesAdvancedRouteYAMLOnly(t *testing.T) {
	stored := routePolicy()
	stored.TransferPolicy.Routes[0].Networks = []string{"mainnet", "testnet"}
	stored.TransferPolicy.Routes[0].LimitsByNetwork = map[string]policy.StoredAmountLimits{
		"mainnet": {
			ReviewAbove: uint64Ptr(10),
			RejectAbove: uint64Ptr(20),
		},
		"testnet": {
			ReviewAbove: uint64Ptr(10),
			RejectAbove: uint64Ptr(30),
		},
	}
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	if m.screen != screenRoutes {
		t.Fatalf("screen = %v, want routes because advanced guard is YAML-only", m.screen)
	}
	if !strings.Contains(m.status, "advanced route is YAML-only") {
		t.Fatalf("status = %q, want advanced YAML-only status", m.status)
	}
	if !strings.Contains(m.err, "limits_by_network") {
		t.Fatalf("err = %q, want limits_by_network reason", m.err)
	}

	limits := m.policy.TransferPolicy.Routes[0].LimitsByNetwork["testnet"]
	if limits.ReviewAbove == nil || *limits.ReviewAbove != 10 ||
		limits.RejectAbove == nil || *limits.RejectAbove != 30 {
		t.Fatalf("LimitsByNetwork not preserved: %+v", m.policy.TransferPolicy.Routes[0].LimitsByNetwork)
	}
}

func TestRouteEditFormRejectsParseError(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	setEditField(&m, "enabled", "maybe")

	updated, cmd := m.applyRouteEdit()
	if cmd != nil {
		t.Fatal("applyRouteEdit() returned command for parse error")
	}
	m = updated.(Model)
	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want route edit", m.screen)
	}
	if !strings.Contains(m.err, "enabled") {
		t.Fatalf("err = %q, want enabled parse error", m.err)
	}
}

func TestRouteEditFormKeepsFormOpenOnValidationError(t *testing.T) {
	store := &fakeStore{validateErr: errors.New("duplicate route id")}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	setEditField(&m, "enabled", "true")

	updated, cmd := m.applyRouteEdit()
	if cmd == nil {
		t.Fatal("applyRouteEdit() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if m.screen != screenRouteEdit {
		t.Fatalf("screen = %v, want route edit after validation error", m.screen)
	}
	if !strings.Contains(m.err, "duplicate route id") {
		t.Fatalf("err = %q, want validation error", m.err)
	}
	if got := m.policy.TransferPolicy.Routes[0].Enabled; got != nil {
		t.Fatalf("route enabled changed to %v despite validation error", got)
	}
}

func TestFriendlyPolicyErrorExplainsAssetSources(t *testing.T) {
	got := friendlyPolicyError(errors.New("invalid policy: transfer_policy: routes[1]: asset_sources requires clawback.allow:true"))
	if !strings.Contains(got, "clear Asset Sources for normal sends") {
		t.Fatalf("friendlyPolicyError() = %q, want normal-send guidance", got)
	}
}

func TestTransferSettingsApplyValidatedChanges(t *testing.T) {
	store := &fakeStore{}
	stored := routePolicy()
	stored.TransferPolicy.BlockedDestinations = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}
	m := New(store, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	updated, _ = m.Update(keyRunes("p"))
	m = updated.(Model)
	if m.screen != screenTransferSettings {
		t.Fatalf("screen = %v, want transfer settings", m.screen)
	}
	setSettingsField(&m, "enabled", "false")
	setSettingsField(&m, "on_no_route", "review")
	setSettingsField(&m, "close_on_no_route", "operator_default")
	setSettingsField(&m, "clawback_on_no_route", "review")

	updated, cmd := m.applyTransferSettings()
	if cmd == nil {
		t.Fatal("applyTransferSettings() returned nil command")
	}
	msg := cmd()
	updated, _ = updated.(Model).Update(msg)
	m = updated.(Model)

	if m.screen != screenTransferSettings {
		t.Fatalf("screen = %v, want transfer settings after save", m.screen)
	}
	if m.policy.TransferPolicy.Enabled == nil || *m.policy.TransferPolicy.Enabled {
		t.Fatalf("enabled = %v, want false", m.policy.TransferPolicy.Enabled)
	}
	if m.policy.TransferPolicy.OnNoRoute == nil || *m.policy.TransferPolicy.OnNoRoute != "review" {
		t.Fatalf("on_no_route = %v, want review", m.policy.TransferPolicy.OnNoRoute)
	}
	if m.policy.TransferPolicy.CloseOnNoRoute == nil || *m.policy.TransferPolicy.CloseOnNoRoute != "operator_default" {
		t.Fatalf("close_on_no_route = %v, want operator_default", m.policy.TransferPolicy.CloseOnNoRoute)
	}
	if m.policy.TransferPolicy.ClawbackOnNoRoute == nil || *m.policy.TransferPolicy.ClawbackOnNoRoute != "review" {
		t.Fatalf("clawback_on_no_route = %v, want review", m.policy.TransferPolicy.ClawbackOnNoRoute)
	}
	if len(m.policy.TransferPolicy.BlockedDestinations) != 1 {
		t.Fatalf("blocked destinations = %+v, want preserved one", m.policy.TransferPolicy.BlockedDestinations)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestTransferSettingsFieldsUseEnterEditors(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("p"))
	m = updated.(Model)
	if m.screen != screenTransferSettings {
		t.Fatalf("screen = %v, want transfer settings", m.screen)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenTransferSettingsChoiceEdit {
		t.Fatalf("screen = %v, want transfer settings choice editor", m.screen)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("enabled choice returned nil auto-save command")
	}
	updated, _ = updated.(Model).Update(cmd())
	m = updated.(Model)
	if got := settingsFieldValue(m, "enabled"); got != "false" {
		t.Fatalf("enabled field = %q, want false", got)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenTransferSettingsChoiceEdit {
		t.Fatalf("screen = %v, want transfer settings choice editor", m.screen)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("on_no_route choice returned nil auto-save command")
	}
	updated, _ = updated.(Model).Update(cmd())
	m = updated.(Model)
	if got := settingsFieldValue(m, "on_no_route"); got != "review" {
		t.Fatalf("on_no_route field = %q, want review", got)
	}

	if m.screen != screenTransferSettings {
		t.Fatalf("screen = %v, want transfer settings after auto-save", m.screen)
	}
	if m.policy.TransferPolicy.Enabled == nil || *m.policy.TransferPolicy.Enabled {
		t.Fatalf("enabled = %v, want false", m.policy.TransferPolicy.Enabled)
	}
	if m.policy.TransferPolicy.OnNoRoute == nil || *m.policy.TransferPolicy.OnNoRoute != "review" {
		t.Fatalf("on_no_route = %v, want review", m.policy.TransferPolicy.OnNoRoute)
	}
	if store.validations != 2 {
		t.Fatalf("validations = %d, want 2", store.validations)
	}
}

func TestTransferSettingsEnabledIsBinaryInUI(t *testing.T) {
	stored := routePolicy()
	stored.TransferPolicy.Enabled = nil
	m := New(&fakeStore{}, stored, "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("p"))
	m = updated.(Model)
	if got := settingsFieldValue(m, "enabled"); got != "false" {
		t.Fatalf("enabled field = %q, want false for unset transfer policy enabled", got)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != screenTransferSettingsChoiceEdit {
		t.Fatalf("screen = %v, want transfer settings choice editor", m.screen)
	}
	view := m.transferSettingsChoiceEditView()
	if strings.Contains(view, "default") || strings.Contains(view, "inherit") {
		t.Fatalf("enabled choice view includes non-binary option:\n%s", view)
	}
	if !strings.Contains(view, "true") || !strings.Contains(view, "false") {
		t.Fatalf("enabled choice view missing binary options:\n%s", view)
	}
}

func TestTransferSettingsEscDuringValidationDiscardsLateResult(t *testing.T) {
	store := &fakeStore{}
	m := New(store, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("p"))
	m = updated.(Model)
	setSettingsField(&m, "on_no_route", "review")

	updated, cmd := m.applyTransferSettings()
	if cmd == nil {
		t.Fatal("applyTransferSettings() returned nil command")
	}
	m = updated.(Model)
	if !m.busy {
		t.Fatal("model should be busy while transfer settings validation is running")
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.busy {
		t.Fatal("model stayed busy after discarding transfer settings")
	}
	if m.screen != screenRoutes {
		t.Fatalf("screen = %v, want routes after discard", m.screen)
	}

	msg := cmd()
	updated, _ = m.Update(msg)
	m = updated.(Model)
	if m.policy.TransferPolicy.OnNoRoute == nil || *m.policy.TransferPolicy.OnNoRoute != "reject" {
		t.Fatalf("late settings apply changed on_no_route to %v", m.policy.TransferPolicy.OnNoRoute)
	}
	if store.validations != 1 {
		t.Fatalf("validations = %d, want 1", store.validations)
	}
}

func TestTransferSettingsRejectsInvalidOnNoRoute(t *testing.T) {
	m := New(&fakeStore{}, routePolicy(), "/tmp/aplane", "default")
	m.cursor = len(m.fields) - 1
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(keyRunes("p"))
	m = updated.(Model)
	setSettingsField(&m, "on_no_route", "approve")

	updated, cmd := m.applyTransferSettings()
	if cmd != nil {
		t.Fatal("applyTransferSettings() returned command for parse error")
	}
	m = updated.(Model)
	if m.screen != screenTransferSettings {
		t.Fatalf("screen = %v, want transfer settings", m.screen)
	}
	if !strings.Contains(m.err, "on_no_route") {
		t.Fatalf("err = %q, want on_no_route parse error", m.err)
	}
}

func keyRunes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func editFieldIndex(t *testing.T, m Model, key string) int {
	t.Helper()
	for i, field := range m.editFields {
		if field.key == key {
			return i
		}
	}
	t.Fatalf("edit field %q not found", key)
	return -1
}

func editFieldByKey(t *testing.T, m Model, key string) routeEditField {
	t.Helper()
	return m.editFields[editFieldIndex(t, m, key)]
}

func setEditField(m *Model, key, value string) {
	for i := range m.editFields {
		if m.editFields[i].key == key {
			m.editFields[i].value = value
			return
		}
	}
}

func setEditAssetField(m *Model, index int, key, value string) {
	if index < 0 || index >= len(m.editAssetRows) {
		return
	}
	switch key {
	case "asset":
		m.editAssetRows[index].asset = value
	case "review_above":
		m.editAssetRows[index].reviewAbove = value
	case "reject_above":
		m.editAssetRows[index].rejectAbove = value
	}
}

func editAssetFieldValue(m Model, index int, key string) string {
	if index < 0 || index >= len(m.editAssetRows) {
		return ""
	}
	switch key {
	case "asset":
		return m.editAssetRows[index].asset
	case "review_above":
		return m.editAssetRows[index].reviewAbove
	case "reject_above":
		return m.editAssetRows[index].rejectAbove
	default:
		return ""
	}
}

func setSettingsField(m *Model, key, value string) {
	for i := range m.settingsFields {
		if m.settingsFields[i].key == key {
			m.settingsFields[i].value = value
			return
		}
	}
}

func settingsFieldValue(m Model, key string) string {
	for _, field := range m.settingsFields {
		if field.key == key {
			return field.value
		}
	}
	return ""
}

func routePolicy() *policy.StoredConfig {
	enabled := true
	onNoRoute := "reject"
	return &policy.StoredConfig{
		TransferPolicy: &policy.StoredTransferPolicy{
			Enabled:   &enabled,
			OnNoRoute: &onNoRoute,
			Routes: []policy.StoredTransferRoute{
				{
					ID:           "treasury_algo",
					Description:  "Treasury payments",
					Networks:     []string{"mainnet"},
					Sources:      []string{"*"},
					Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
					Destinations: []string{"self"},
				},
			},
		},
	}
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}

func renderedLineCount(s string) int {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return 0
	}
	return len(strings.Split(s, "\n"))
}

func viewHasFieldValueSource(view, label, value, source string) bool {
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, label) &&
			strings.Contains(line, value) &&
			strings.Contains(line, source) {
			return true
		}
	}
	return false
}

var ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func assertHomeSourceColumnAligned(t *testing.T, view string) {
	t.Helper()
	lines := strings.Split(stripANSI(view), "\n")
	sourceColumn := -1
	for _, line := range lines {
		if strings.Contains(line, "Setting") && strings.Contains(line, "Value") && strings.Contains(line, "Source") {
			sourceColumn = strings.Index(line, "Source")
			break
		}
	}
	if sourceColumn < 0 {
		t.Fatalf("home view missing Source header:\n%s", view)
	}
	for _, source := range []string{"default", "explicit", "absent"} {
		afterHeader := false
		for _, line := range lines {
			if strings.Contains(line, "Setting") && strings.Contains(line, "Value") && strings.Contains(line, "Source") {
				afterHeader = true
				continue
			}
			if !afterHeader || strings.Contains(line, "keys:") {
				continue
			}
			if !strings.Contains(line, source) || strings.Contains(line, "Source") {
				continue
			}
			if got := strings.Index(line, source); got != sourceColumn {
				t.Fatalf("source %q starts at column %d, want %d:\n%s", source, got, sourceColumn, view)
			}
		}
	}
}

func stripANSI(s string) string {
	return ansiEscapeRE.ReplaceAllString(s, "")
}

type fakeStore struct {
	saves       int
	validations int
	saveErr     error
	validateErr error
}

func (f fakeStore) Load(context.Context) (*policy.StoredConfig, error) {
	return &policy.StoredConfig{}, nil
}

func (f *fakeStore) Save(context.Context, *policy.StoredConfig) error {
	f.saves++
	return f.saveErr
}

func (f *fakeStore) Validate(context.Context, *policy.StoredConfig) error {
	f.validations++
	return f.validateErr
}

type passphraseFakeStore struct {
	fakeStore
	passphrase []byte
}

func (f *passphraseFakeStore) RequiresPassphraseForSave() bool {
	return len(f.passphrase) == 0
}

func (f *passphraseFakeStore) SetPassphrase(passphrase []byte) {
	f.ClearPassphrase()
	f.passphrase = append([]byte(nil), passphrase...)
}

func (f *passphraseFakeStore) HasPassphrase() bool {
	return len(f.passphrase) > 0
}

func (f *passphraseFakeStore) ClearPassphrase() {
	for i := range f.passphrase {
		f.passphrase[i] = 0
	}
	f.passphrase = nil
}
