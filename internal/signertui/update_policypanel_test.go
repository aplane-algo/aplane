// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	tea "github.com/charmbracelet/bubbletea"
)

func TestValidatePolicySettingValue(t *testing.T) {
	tests := []struct {
		key   string
		value string
		ok    bool
	}{
		{key: adminproto.PolicySettingMaxFeeMicroAlgos, value: "", ok: true},
		{key: adminproto.PolicySettingMaxFeeMicroAlgos, value: "1234", ok: true},
		{key: adminproto.PolicySettingMaxFeeMicroAlgos, value: "12a", ok: false},
	}

	for _, tc := range tests {
		err := validatePolicySettingValue(tc.key, tc.value)
		if tc.ok && err != nil {
			t.Fatalf("validatePolicySettingValue(%q, %q) error = %v, want nil", tc.key, tc.value, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("validatePolicySettingValue(%q, %q) error = nil, want failure", tc.key, tc.value)
		}
	}
}

func TestValidatePolicyASAAmounts(t *testing.T) {
	tests := []struct {
		value string
		ok    bool
	}{
		{value: "", ok: true},
		{value: "123:45, 456:78", ok: true},
		{value: "123:0.5", ok: true},
		{value: "usdc:5", ok: false},
		{value: "123", ok: false},
		{value: "123:abc", ok: false},
	}

	for _, tc := range tests {
		err := validatePolicyASAAmounts(tc.value)
		if tc.ok && err != nil {
			t.Fatalf("validatePolicyASAAmounts(%q) error = %v, want nil", tc.value, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("validatePolicyASAAmounts(%q) error = nil, want failure", tc.value)
		}
	}
}

func TestRenderPolicyPanelSeparatesRejectionAndApprovalSections(t *testing.T) {
	m := Model{
		policySettings: &PolicySettings{
			AlwaysReviewWarnings:        true,
			RejectForeignRekey:          true,
			AutoApproveSelfNoOpTransfer: true,
		},
	}

	rendered := stripANSI(m.renderPolicyPanel())
	rejection := strings.Index(rendered, "Auto-Rejection")
	review := strings.Index(rendered, "Always Review")
	approval := strings.Index(rendered, "Policy Auto-Approve")
	guards := strings.Index(rendered, "Transfer Guards")
	rejectRow := strings.Index(rendered, "Reject foreign rekey")
	guardRow := strings.Index(rendered, "Transfer guards")
	reviewRow := strings.Index(rendered, "Review warning txns")
	approveRow := strings.Index(rendered, "Approve self no-op transfer")

	if rejection < 0 {
		t.Fatalf("renderPolicyPanel() missing Auto-Rejection section:\n%s", rendered)
	}
	if review < 0 {
		t.Fatalf("renderPolicyPanel() missing Always Review section:\n%s", rendered)
	}
	if approval < 0 {
		t.Fatalf("renderPolicyPanel() missing Policy Auto-Approve section:\n%s", rendered)
	}
	if guards < 0 {
		t.Fatalf("renderPolicyPanel() missing Transfer Guards section:\n%s", rendered)
	}
	if rejection >= rejectRow || rejectRow >= guards || guards >= guardRow || guardRow >= review || review >= reviewRow || reviewRow >= approval || approval >= approveRow {
		t.Fatalf("policy section order is wrong:\n%s", rendered)
	}
}

func TestHandlePolicyASAModalSaveStartsAtomicUpdate(t *testing.T) {
	m := Model{
		viewState:            ViewPolicyASAModal,
		policyASAMode:        policyASAModeLimits,
		policyASAFocus:       3,
		policyASANetworks:    []string{"testnet"},
		policyASASelectedNet: "testnet",
		policyASAEntries:     []policyASAEntry{{AssetID: 3, ReviewAmount: "2", MaxAmount: "4"}},
		policyASAReviewValues: map[string]string{
			"testnet": "3:2",
		},
		policyASAValues: map[string]string{
			"testnet": "3:4",
		},
	}

	nextModel, cmd := m.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := nextModel.(Model)
	if cmd == nil {
		t.Fatal("handlePolicyASAModalKeys(save) cmd = nil, want command")
	}
	if got.viewState != ViewPolicyASAModal {
		t.Fatalf("viewState = %v, want ViewPolicyASAModal while save is pending", got.viewState)
	}
	if got.lastError != "" {
		t.Fatalf("lastError = %q, want empty", got.lastError)
	}
	if !got.policyASAPending {
		t.Fatal("policyASAPending = false, want true")
	}
	if got.policyASAPendingValues["testnet"] != "3:4" {
		t.Fatalf("policyASAPendingValues[testnet] = %q, want 3:4", got.policyASAPendingValues["testnet"])
	}
	if got.policyASAReviewPendingValues["testnet"] != "3:2" {
		t.Fatalf("policyASAReviewPendingValues[testnet] = %q, want 3:2", got.policyASAReviewPendingValues["testnet"])
	}
}

func TestPolicyASAUpdateSuccessAppliesPendingSnapshot(t *testing.T) {
	m := Model{
		viewState:        ViewPolicyASAModal,
		policyASAPending: true,
		policyASAPendingValues: map[string]string{
			"mainnet": "",
			"testnet": "10458941:1, 753507995:1",
			"betanet": "",
		},
		policyASAReviewPendingValues: map[string]string{
			"testnet": "10458941:0.5",
		},
	}

	next, _ := m.Update(PolicySettingUpdatedMsg{Success: true, Key: policyPanelActionTransferGuards})
	got := next.(Model)
	if got.policyASAPending {
		t.Fatal("policyASAPending = true, want false")
	}
	if got.viewState != ViewPolicyPanel {
		t.Fatalf("viewState = %v, want ViewPolicyPanel", got.viewState)
	}
	if got.policySettings == nil {
		t.Fatal("policySettings = nil, want applied ASA snapshot")
	}
	if got.policySettings.MaxASAAmounts["testnet"] != "10458941:1, 753507995:1" {
		t.Fatalf("MaxASAAmounts[testnet] = %q, want saved value", got.policySettings.MaxASAAmounts["testnet"])
	}
	if got.policySettings.ReviewASAAmounts["testnet"] != "10458941:0.5" {
		t.Fatalf("ReviewASAAmounts[testnet] = %q, want saved value", got.policySettings.ReviewASAAmounts["testnet"])
	}
}

func TestPolicyASAUpdateFailureKeepsModalOpen(t *testing.T) {
	m := Model{
		viewState:        ViewPolicyASAModal,
		policyASAPending: true,
		policyASAPendingValues: map[string]string{
			"testnet": "10458941:1, 753507995:1",
		},
	}

	next, _ := m.Update(PolicySettingUpdatedMsg{Success: false, Key: policyPanelActionTransferGuards, Error: "asset not found"})
	got := next.(Model)
	if got.policyASAPending {
		t.Fatal("policyASAPending = true, want false")
	}
	if got.viewState != ViewPolicyASAModal {
		t.Fatalf("viewState = %v, want ViewPolicyASAModal", got.viewState)
	}
	if got.lastError == "" {
		t.Fatal("lastError is empty, want failure message")
	}
}

func TestStartPolicyASAModalUsesLatestSnapshot(t *testing.T) {
	m := Model{
		policySettings: &PolicySettings{
			PolicyNetworks: []string{"testnet", "voi_mainnet"},
			ReviewASAAmounts: map[string]string{
				"testnet": "10458941:0.5",
			},
			MaxASAAmounts: map[string]string{
				"testnet": "10458941:1, 753507995:1",
				"mainnet": "31566704:1",
			},
			ReviewAlgoPayments: map[string]string{
				"testnet": "5",
			},
			MaxAlgoPayments: map[string]string{
				"testnet": "10.5",
			},
			PolicyASAMetadata: map[string][]ASAMetadataInfo{
				"testnet": {
					{AssetID: 10458941, UnitName: "USDC", Name: "USD Coin", Decimals: 6, Source: "cache"},
				},
			},
		},
	}

	got := m.startPolicyASAModal()
	if got.policyASAValues["testnet"] != "10458941:1, 753507995:1" {
		t.Fatalf("policyASAValues[testnet] = %q, want saved value", got.policyASAValues["testnet"])
	}
	if got.policyASAReviewValues["testnet"] != "10458941:0.5" {
		t.Fatalf("policyASAReviewValues[testnet] = %q, want saved value", got.policyASAReviewValues["testnet"])
	}
	if _, ok := got.policyASAValues["mainnet"]; ok {
		t.Fatal("policyASAValues includes mainnet, want only configured policy networks")
	}
	if strings.Join(got.policyASANetworks, ",") != "testnet,voi_mainnet" {
		t.Fatalf("policyASANetworks = %v, want [testnet voi_mainnet]", got.policyASANetworks)
	}
	if got.policyAlgoValues["testnet"] != "10.5" {
		t.Fatalf("policyAlgoValues[testnet] = %q, want 10.5", got.policyAlgoValues["testnet"])
	}
	if got.policyAlgoReviewValues["testnet"] != "5" {
		t.Fatalf("policyAlgoReviewValues[testnet] = %q, want 5", got.policyAlgoReviewValues["testnet"])
	}
	got.openPolicyASANetwork("testnet")
	if got.policyASAEntries[0].Meta == nil || got.policyASAEntries[0].Meta.UnitName != "USDC" {
		t.Fatalf("policyASAEntries[0].Meta = %+v, want USDC metadata", got.policyASAEntries[0].Meta)
	}
	rendered := got.renderPolicyASALimits()
	if !strings.Contains(rendered, "USDC") {
		t.Fatalf("rendered ASA guards do not include symbol USDC:\n%s", rendered)
	}
	if !strings.Contains(rendered, "ALGO") || !strings.Contains(rendered, "10.5") {
		t.Fatalf("rendered transfer guards do not include ALGO guard:\n%s", rendered)
	}
	if strings.Contains(rendered, "ALGO payment max") {
		t.Fatalf("rendered transfer guards include redundant ALGO label:\n%s", rendered)
	}
}

func TestPolicyASANetworkSelectionOpensLimitList(t *testing.T) {
	m := Model{
		viewState:         ViewPolicyASAModal,
		policyASAMode:     policyASAModeNetworks,
		policyASAFocus:    1,
		policyASANetworks: []string{"mainnet", "testnet"},
		policyASAReviewValues: map[string]string{
			"testnet": "10458941:0.5",
		},
		policyASAValues: map[string]string{
			"testnet": "10458941:1",
		},
	}

	next, cmd := m.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("network selection returned cmd = %v, want nil", cmd)
	}
	got := next.(Model)
	if got.policyASAMode != policyASAModeLimits {
		t.Fatalf("policyASAMode = %v, want limits mode", got.policyASAMode)
	}
	if got.policyASASelectedNet != "testnet" {
		t.Fatalf("policyASASelectedNet = %q, want testnet", got.policyASASelectedNet)
	}
	if len(got.policyASAEntries) != 1 || got.policyASAEntries[0].AssetID != 10458941 {
		t.Fatalf("policyASAEntries = %+v, want existing testnet ASA guard", got.policyASAEntries)
	}
}

func TestPolicyASASymbolFlowChoosesCachedDuplicateAndSavesNumericID(t *testing.T) {
	m := Model{
		viewState:            ViewPolicyASAModal,
		policyASAMode:        policyASAModeAddRef,
		policyASANetworks:    []string{"testnet"},
		policyASASelectedNet: "testnet",
		policyASAValues:      map[string]string{"testnet": ""},
	}

	next, _ := m.Update(ASAMetadataResultsMsg{
		Network: "testnet",
		Query:   "BOB",
		Results: []ASAMetadataInfo{
			{AssetID: 752602672, UnitName: "BOB", Name: "Bob A", Decimals: 6, Source: "cache"},
			{AssetID: 753507995, UnitName: "BOB", Name: "Bob B", Decimals: 6, Source: "cache"},
		},
	})
	got := next.(Model)
	if got.policyASAMode != policyASAModeChoose {
		t.Fatalf("after duplicate search policyASAMode = %v, want choose", got.policyASAMode)
	}

	next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyDown})
	got = next.(Model)
	next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.policyASAMode != policyASAModeAddAmount {
		t.Fatalf("after choosing symbol policyASAMode = %v, want add amount", got.policyASAMode)
	}
	if got.policyASASelectedAsset == nil || got.policyASASelectedAsset.AssetID != 753507995 {
		t.Fatalf("selected asset = %+v, want ASA 753507995", got.policyASASelectedAsset)
	}

	got.policyASADenyInput = "1.25"
	next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.policyASAMode != policyASAModeLimits {
		t.Fatalf("after amount policyASAMode = %v, want limits", got.policyASAMode)
	}
	if got.policyASAValues["testnet"] != "753507995:1.25" {
		t.Fatalf("policyASAValues[testnet] = %q, want numeric persisted value", got.policyASAValues["testnet"])
	}
	if got.policyASAFocus != 3 {
		t.Fatalf("policyASAFocus = %d, want Save changes row", got.policyASAFocus)
	}

	next, cmd := got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	got = next.(Model)
	if cmd == nil {
		t.Fatal("save command = nil, want update command")
	}
	if !got.policyASAPending {
		t.Fatal("policyASAPending = false, want true")
	}
	if got.policyASAPendingValues["testnet"] != "753507995:1.25" {
		t.Fatalf("pending testnet value = %q, want numeric ASA guard", got.policyASAPendingValues["testnet"])
	}
}

func TestPolicyASANumericResolveFlowAddsDisplayAmount(t *testing.T) {
	m := Model{
		viewState:            ViewPolicyASAModal,
		policyASAMode:        policyASAModeAddRef,
		policyASANetworks:    []string{"testnet"},
		policyASASelectedNet: "testnet",
		policyASAValues:      map[string]string{"testnet": ""},
	}

	next, _ := m.Update(ASAMetadataResultMsg{
		Network: "testnet",
		Asset: ASAMetadataInfo{
			AssetID:  10458941,
			UnitName: "USDC",
			Name:     "USD Coin",
			Decimals: 6,
			Source:   "cache",
		},
	})
	got := next.(Model)
	if got.policyASAMode != policyASAModeAddAmount {
		t.Fatalf("after resolve policyASAMode = %v, want add amount", got.policyASAMode)
	}

	for _, r := range "0.5" {
		if got.policyASAAmountField != 0 {
			t.Fatalf("policyASAAmountField = %d, want review field", got.policyASAAmountField)
		}
		next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		got = next.(Model)
	}
	next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.policyASAReviewValues["testnet"] != "10458941:0.5" {
		t.Fatalf("policyASAReviewValues[testnet] = %q, want 10458941:0.5", got.policyASAReviewValues["testnet"])
	}
	if got.policyASAFocus != 3 {
		t.Fatalf("policyASAFocus = %d, want Save changes row", got.policyASAFocus)
	}
}

func TestPolicyASAAlgoLimitFlowSavesNetworkScopedValue(t *testing.T) {
	m := Model{
		viewState:              ViewPolicyASAModal,
		policyASAMode:          policyASAModeLimits,
		policyASAFocus:         0,
		policyASANetworks:      []string{"testnet"},
		policyASASelectedNet:   "testnet",
		policyASAValues:        map[string]string{"testnet": ""},
		policyASAReviewValues:  map[string]string{"testnet": ""},
		policyAlgoValues:       map[string]string{"testnet": ""},
		policyAlgoReviewValues: map[string]string{"testnet": ""},
	}

	next, _ := m.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.policyASAMode != policyASAModeAlgoAmount {
		t.Fatalf("policyASAMode = %v, want ALGO amount mode", got.policyASAMode)
	}
	next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyTab})
	got = next.(Model)
	for _, r := range "10.5" {
		next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		got = next.(Model)
	}
	next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.policyAlgoValues["testnet"] != "10.5" {
		t.Fatalf("policyAlgoValues[testnet] = %q, want 10.5", got.policyAlgoValues["testnet"])
	}
	if got.policyASAFocus != 2 {
		t.Fatalf("policyASAFocus = %d, want Save changes row", got.policyASAFocus)
	}

	next, cmd := got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if cmd == nil {
		t.Fatal("save command = nil, want update command")
	}
	if got.policyAlgoPendingValues["testnet"] != "10.5" {
		t.Fatalf("policyAlgoPendingValues[testnet] = %q, want 10.5", got.policyAlgoPendingValues["testnet"])
	}
}

func TestPolicyASAEscapeFromLimitListDiscardsDraft(t *testing.T) {
	m := Model{
		policySettings: &PolicySettings{
			PolicyNetworks:  []string{"testnet"},
			MaxAlgoPayments: map[string]string{"testnet": "5"},
			MaxASAAmounts:   map[string]string{"testnet": "10458941:1"},
		},
	}
	m = m.startPolicyASAModal()
	m.openPolicyASANetwork("testnet")

	next, _ := m.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	for _, r := range "1" {
		next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		got = next.(Model)
	}
	next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.policyAlgoReviewValues["testnet"] != "1" {
		t.Fatalf("draft ALGO review value = %q, want 1", got.policyAlgoReviewValues["testnet"])
	}

	next, _ = got.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got = next.(Model)
	if got.policyASAMode != policyASAModeNetworks {
		t.Fatalf("policyASAMode = %v, want networks", got.policyASAMode)
	}
	if got.policyAlgoValues["testnet"] != "5" {
		t.Fatalf("policyAlgoValues[testnet] = %q, want persisted value 5 after discard", got.policyAlgoValues["testnet"])
	}
}

func TestPolicyASASymbolSearchFailuresStayInEntryMode(t *testing.T) {
	tests := []struct {
		name string
		msg  ASAMetadataResultsMsg
	}{
		{
			name: "not found",
			msg:  ASAMetadataResultsMsg{Network: "testnet", Query: "BOB"},
		},
		{
			name: "server error",
			msg:  ASAMetadataResultsMsg{Network: "testnet", Query: "BOB", Error: "cache unavailable"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := Model{
				viewState:            ViewPolicyASAModal,
				policyASAMode:        policyASAModeAddRef,
				policyASASelectedNet: "testnet",
				policyASAInput:       "BOB",
			}
			next, _ := m.Update(tc.msg)
			got := next.(Model)
			if got.policyASAMode != policyASAModeAddRef {
				t.Fatalf("policyASAMode = %v, want add ref", got.policyASAMode)
			}
			if got.lastError == "" {
				t.Fatal("lastError is empty, want search failure")
			}
		})
	}
}

func TestPolicyASARejectsTooManyDisplayDecimals(t *testing.T) {
	m := Model{
		viewState:              ViewPolicyASAModal,
		policyASAMode:          policyASAModeAddAmount,
		policyASASelectedNet:   "testnet",
		policyASAReviewInput:   "1.001",
		policyASASelectedAsset: &ASAMetadataInfo{AssetID: 1, Decimals: 2},
	}

	next, _ := m.handlePolicyASAModalKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if got.policyASAMode != policyASAModeAddAmount {
		t.Fatalf("policyASAMode = %v, want add amount after invalid decimal", got.policyASAMode)
	}
	if got.lastError != fmt.Sprintf("%s must have at most %d decimal places", "ASA review threshold", 2) {
		t.Fatalf("lastError = %q, want decimal-place validation error", got.lastError)
	}
}
