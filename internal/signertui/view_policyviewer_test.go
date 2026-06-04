// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyview"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestPolicySnapshotMsgBuildsReadOnlyPolicyView(t *testing.T) {
	yamlText := `reject_foreign_rekey: true
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  asset_sets:
    usdc:
      testnet: [10458941]
  routes:
    - id: test_algo
      description: Test guard
      networks: [testnet]
      sources: ["*"]
      assets: ["algo"]
      destinations: ["M75..."]
    - id: test_usdc
      description: Test guard
      networks: [testnet]
      sources: ["*"]
      assets: ["@usdc"]
      destinations: ["M75..."]
`

	m := Model{viewState: ViewPolicyViewer}
	next, _ := m.Update(PolicySnapshotMsg{Snapshot: PolicySnapshot{
		Success:      true,
		IdentityID:   "default",
		PolicyYAML:   yamlText,
		PolicySHA256: "abc123",
		Canonical:    true,
	}})
	got := next.(Model)

	if !got.policyViewLoaded {
		t.Fatalf("policyViewLoaded = false, error %q", got.policyViewError)
	}
	if len(got.policyView.TransferGuards) != 1 {
		t.Fatalf("TransferGuards = %d, want 1", len(got.policyView.TransferGuards))
	}
	if got.policyView.TransferGuards[0].ID != "test" {
		t.Fatalf("guard ID = %q, want test", got.policyView.TransferGuards[0].ID)
	}
}

func TestRenderPolicyViewerShowsOverviewAndGuardNames(t *testing.T) {
	enabled := true
	m := Model{
		viewState:        ViewPolicyViewer,
		width:            120,
		height:           32,
		policyViewLoaded: true,
		policySnapshot: &PolicySnapshot{
			IdentityID:   "default",
			PolicySHA256: "0123456789abcdef",
			Canonical:    true,
		},
		policyView: policyview.Model{
			Fields: []policyview.FieldRow{
				{Key: "reject_foreign_rekey", Label: "Reject foreign rekey", Value: "true", Source: "explicit"},
				{Key: "reject_close_remainder", Label: "Reject close remainder", Value: "false", Source: "default"},
			},
			TransferSummary: "enabled=true routes=2",
			TransferGuards: []policyview.TransferGuardGroup{
				{
					ID:           "test",
					Description:  "Test guard",
					Enabled:      &enabled,
					Networks:     []string{"testnet"},
					Sources:      []string{"*"},
					Destinations: []string{"M75..."},
					AssetRows: []policyview.TransferGuardAssetRow{
						{Asset: "algo"},
						{Asset: "@usdc"},
					},
				},
			},
		},
	}

	rendered := stripANSI(m.renderPolicyViewer())
	for _, want := range []string{
		"Read-only active signer policy",
		"Identity: default",
		"Reject foreign rekey",
		"Transfer routing",
		"test",
		"Test guard",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("renderPolicyViewer() missing %q:\n%s", want, rendered)
		}
	}
	if !policyViewerHasBlankLineBefore(rendered, "Transfer guards") {
		t.Fatalf("renderPolicyViewer() missing blank line above transfer guards:\n%s", rendered)
	}
}

func TestRenderPolicyViewerOverviewGuardListStopsAtStatus(t *testing.T) {
	enabled := true
	m := Model{
		viewState:        ViewPolicyViewer,
		width:            120,
		height:           32,
		policyViewLoaded: true,
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{
				{
					ID:           "test",
					Description:  "Test guard description",
					Enabled:      &enabled,
					Networks:     []string{"mainnet"},
					Sources:      []string{"*"},
					Destinations: []string{"M75..."},
					AssetRows: []policyview.TransferGuardAssetRow{
						{Asset: "algo"},
						{Asset: "@usdc"},
					},
				},
			},
		},
	}

	rendered := stripANSI(m.renderPolicyViewer())
	for _, line := range strings.Split(rendered, "\n") {
		if !strings.Contains(line, "> test") {
			continue
		}
		if strings.Contains(line, "assets:") || strings.Contains(line, "nets:") || strings.Contains(line, "dest:") {
			t.Fatalf("guard list row still shows route detail columns:\n%s", rendered)
		}
		return
	}
	t.Fatalf("renderPolicyViewer() missing selected guard row:\n%s", rendered)
}

func policyViewerHasBlankLineBefore(rendered, target string) bool {
	lines := strings.Split(rendered, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != target {
			continue
		}
		return i > 0 && strings.TrimSpace(lines[i-1]) == ""
	}
	return false
}

func policyViewerGuardFieldIndex(key string) int {
	m := Model{
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{
				{
					Networks:     []string{"mainnet"},
					Sources:      []string{"*"},
					Destinations: []string{"self"},
				},
			},
		},
	}
	for i, field := range m.policyViewerGuardFields() {
		if field.key == key {
			return i
		}
	}
	return 0
}

func TestRenderPolicyViewerGuardDetailShowsGuardNameOnce(t *testing.T) {
	m := Model{
		viewState:        ViewPolicyViewer,
		width:            120,
		height:           32,
		policyViewLoaded: true,
		policyViewMode:   policyViewerModeGuardDetail,
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{
				{
					ID:           "guardname",
					Description:  "Test guard",
					Networks:     []string{"mainnet"},
					Sources:      []string{"*"},
					Destinations: []string{"M75..."},
					AssetRows: []policyview.TransferGuardAssetRow{
						{Asset: "algo"},
					},
				},
			},
		},
	}

	rendered := stripANSI(m.renderPolicyViewer())
	if got := strings.Count(rendered, "guardname"); got != 1 {
		t.Fatalf("guard name count = %d, want 1:\n%s", got, rendered)
	}
	if !strings.Contains(rendered, "Guard 1 of 1") {
		t.Fatalf("renderPolicyViewer() missing guard position:\n%s", rendered)
	}
}

func TestRenderPolicyViewerGuardDetailSummarizesMultiValueFields(t *testing.T) {
	m := Model{
		viewState:        ViewPolicyViewer,
		width:            120,
		height:           32,
		policyViewLoaded: true,
		policyViewMode:   policyViewerModeGuardDetail,
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{
				{
					ID:          "guardname",
					Description: "Test guard",
					Networks:    []string{"mainnet"},
					Sources: []string{
						"SOURCEONEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						"SOURCETWOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					},
					Destinations: []string{
						"M75AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						"JHXBYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
					},
					AssetRows: []policyview.TransferGuardAssetRow{{Asset: "algo"}},
				},
			},
		},
	}

	rendered := stripANSI(m.renderPolicyViewer())
	for _, want := range []string{
		"Networks           mainnet",
		"Sources            (2)",
		"Destinations       (2)",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("renderPolicyViewer() missing %q:\n%s", want, rendered)
		}
	}
	for _, leaked := range []string{"SOURCEONE", "SOURCETWO", "M75AAAAAAAA", "JHXBYYYY"} {
		if strings.Contains(rendered, leaked) {
			t.Fatalf("renderPolicyViewer() leaked multi-value field item %q:\n%s", leaked, rendered)
		}
	}
}

func TestPolicyViewerGuardDetailOpensReadOnlyListPopup(t *testing.T) {
	m := Model{
		viewState:                    ViewPolicyViewer,
		width:                        120,
		height:                       32,
		policyViewLoaded:             true,
		policyViewMode:               policyViewerModeGuardDetail,
		policyViewSelectedGuardField: policyViewerGuardFieldIndex("destinations"),
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{
				{
					ID:       "guardname",
					Networks: []string{"mainnet"},
					Sources:  []string{"*"},
					Destinations: []string{
						"M75AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						"JHXBYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
					},
				},
			},
		},
	}

	next, cmd := m.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if cmd != nil {
		t.Fatalf("enter cmd = %v, want nil", cmd)
	}
	if got.policyViewListPopupField != "destinations" {
		t.Fatalf("policyViewListPopupField = %q, want destinations", got.policyViewListPopupField)
	}
	rendered := stripANSI(got.renderPolicyViewer())
	for _, want := range []string{
		"Destinations",
		"M75AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"JHXBYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("renderPolicyViewer() missing %q:\n%s", want, rendered)
		}
	}
	if got := strings.Count(rendered, "Read-only"); got != 1 {
		t.Fatalf("renderPolicyViewer() Read-only count = %d, want only screen subtitle:\n%s", got, rendered)
	}

	next, cmd = got.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	got = next.(Model)
	if cmd != nil {
		t.Fatalf("read-only popup key cmd = %v, want nil", cmd)
	}
	if got.policyViewListPopupField != "destinations" {
		t.Fatalf("read-only popup field = %q, want still open", got.policyViewListPopupField)
	}

	next, _ = got.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyEsc})
	got = next.(Model)
	if got.policyViewListPopupField != "" {
		t.Fatalf("policyViewListPopupField = %q, want closed", got.policyViewListPopupField)
	}
}

func TestPolicyViewerGuardDetailDoesNotOpenPopupForSingleListValue(t *testing.T) {
	m := Model{
		viewState:                    ViewPolicyViewer,
		width:                        120,
		height:                       32,
		policyViewLoaded:             true,
		policyViewMode:               policyViewerModeGuardDetail,
		policyViewSelectedGuardField: policyViewerGuardFieldIndex("destinations"),
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{
				{
					ID:           "guardname",
					Networks:     []string{"mainnet"},
					Sources:      []string{"*"},
					Destinations: []string{"self"},
				},
			},
		},
	}

	rendered := stripANSI(m.renderPolicyViewer())
	if !strings.Contains(rendered, "Destinations       self") {
		t.Fatalf("renderPolicyViewer() missing single destination value:\n%s", rendered)
	}

	next, cmd := m.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(Model)
	if cmd != nil {
		t.Fatalf("enter cmd = %v, want nil", cmd)
	}
	if got.policyViewListPopupField != "" {
		t.Fatalf("policyViewListPopupField = %q, want no popup for a single value", got.policyViewListPopupField)
	}
}

func TestRenderPolicyViewerOverviewShowsDescriptionInsteadOfGuardPreview(t *testing.T) {
	m := Model{
		viewState:        ViewPolicyViewer,
		width:            120,
		height:           32,
		policyViewLoaded: true,
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{
				{
					ID:           "guardname",
					Description:  "Test guard description",
					Networks:     []string{"mainnet"},
					Sources:      []string{"*"},
					Destinations: []string{"M75..."},
					AssetRows: []policyview.TransferGuardAssetRow{
						{Asset: "algo"},
					},
				},
			},
		},
	}

	rendered := stripANSI(m.renderPolicyViewer())
	if !strings.Contains(rendered, "Description: Test guard description") {
		t.Fatalf("renderPolicyViewer() missing selected guard description:\n%s", rendered)
	}
	for _, unwanted := range []string{"Networks:", "Sources:", "Destinations:", "Close remainder:"} {
		if strings.Contains(rendered, unwanted) {
			t.Fatalf("renderPolicyViewer() still shows guard preview line %q:\n%s", unwanted, rendered)
		}
	}
}

func TestPolicyViewerPinsHelpAndStatusToPaneBottom(t *testing.T) {
	enabled := true
	m := Model{
		viewState:               ViewPolicyViewer,
		width:                   120,
		height:                  24,
		connectionState:         ConnectionConnected,
		signerStatusKnown:       true,
		policyViewLoaded:        true,
		policySnapshot:          &PolicySnapshot{IdentityID: "default", PolicySHA256: "abc123", Canonical: true},
		policyViewSelectedGuard: 0,
		policyView: policyview.Model{
			Fields: []policyview.FieldRow{
				{Key: "reject_foreign_rekey", Label: "Reject foreign rekey", Value: "true", Source: "explicit"},
			},
			TransferSummary: "enabled=true routes=1",
			TransferGuards: []policyview.TransferGuardGroup{
				{
					ID:           "test",
					Description:  "Test guard",
					Enabled:      &enabled,
					Networks:     []string{"testnet"},
					Sources:      []string{"*"},
					Destinations: []string{"M75..."},
					AssetRows:    []policyview.TransferGuardAssetRow{{Asset: "algo"}},
				},
			},
		},
	}

	rendered := stripANSI(m.View())
	lines := strings.Split(strings.TrimRight(rendered, "\n"), "\n")
	if got := len(lines); got != m.height {
		t.Fatalf("View() rendered %d lines, want %d:\n%s", got, m.height, rendered)
	}
	helpLine := strings.TrimSpace(lines[len(lines)-2])
	if !strings.Contains(helpLine, "up/down: Select guard") || !strings.Contains(helpLine, "esc: Back") {
		t.Fatalf("hotkey line not pinned above status bar: %q\n%s", helpLine, rendered)
	}
	statusLine := strings.TrimSpace(lines[len(lines)-1])
	if !strings.Contains(statusLine, "Connected") || !strings.Contains(statusLine, "Signer Unlocked") {
		t.Fatalf("status line not pinned at bottom: %q\n%s", statusLine, rendered)
	}
}

func TestPolicyViewerIgnoresMutationKeys(t *testing.T) {
	m := Model{
		viewState:               ViewPolicyViewer,
		policyViewLoaded:        true,
		policyViewSelectedGuard: 0,
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{{ID: "test"}},
		},
	}

	for _, key := range []rune{'s', 'n', 'd', 'x'} {
		next, cmd := m.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
		got := next.(Model)
		if got.viewState != ViewPolicyViewer {
			t.Fatalf("key %q viewState = %v, want ViewPolicyViewer", key, got.viewState)
		}
		if cmd != nil {
			t.Fatalf("key %q cmd = %v, want nil", key, cmd)
		}
	}
}

func TestPolicyViewerLeftRightSwitchModesAndTabIsIgnored(t *testing.T) {
	m := Model{
		viewState:        ViewPolicyViewer,
		policyViewLoaded: true,
		policyViewMode:   policyViewerModeOverview,
		policyView: policyview.Model{
			TransferGuards: []policyview.TransferGuardGroup{{ID: "test"}},
		},
	}

	next, cmd := m.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyRight})
	got := next.(Model)
	if cmd != nil {
		t.Fatalf("right cmd = %v, want nil", cmd)
	}
	if got.policyViewMode != policyViewerModeGuardDetail {
		t.Fatalf("right from overview mode = %v, want guard detail", got.policyViewMode)
	}

	next, cmd = got.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyRight})
	got = next.(Model)
	if cmd != nil {
		t.Fatalf("second right cmd = %v, want nil", cmd)
	}
	if got.policyViewMode != policyViewerModeYAML {
		t.Fatalf("right from guard mode = %v, want YAML", got.policyViewMode)
	}

	next, cmd = got.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyLeft})
	got = next.(Model)
	if cmd != nil {
		t.Fatalf("left cmd = %v, want nil", cmd)
	}
	if got.policyViewMode != policyViewerModeGuardDetail {
		t.Fatalf("left from YAML mode = %v, want guard detail", got.policyViewMode)
	}

	next, cmd = got.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyTab})
	got = next.(Model)
	if cmd != nil {
		t.Fatalf("tab cmd = %v, want nil", cmd)
	}
	if got.policyViewMode != policyViewerModeGuardDetail {
		t.Fatalf("tab mode = %v, want unchanged guard detail", got.policyViewMode)
	}
}

func TestPolicyViewerLoadWorkflowReadsFileAndConfirms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	yamlText := "max_fee_microalgos: 4321\n"
	if err := os.WriteFile(path, []byte(yamlText), 0o600); err != nil {
		t.Fatalf("WriteFile(policy.yaml) error = %v", err)
	}

	m := Model{
		viewState:        ViewPolicyViewer,
		width:            100,
		height:           24,
		policyViewLoaded: true,
		policySnapshot:   &PolicySnapshot{Success: true, PolicySHA256: "abc123"},
	}
	next, cmd := m.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	got := next.(Model)
	if got.policyLoadState != policyLoadPath {
		t.Fatalf("policyLoadState = %v, want policyLoadPath", got.policyLoadState)
	}
	if cmd != nil {
		t.Fatalf("load key cmd = %v, want nil before path entry", cmd)
	}

	for _, r := range path {
		next, cmd = got.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		got = next.(Model)
		if cmd != nil {
			t.Fatalf("path key %q returned unexpected cmd", string(r))
		}
	}
	next, cmd = got.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyEnter})
	got = next.(Model)
	if got.policyLoadState != policyLoadReading {
		t.Fatalf("policyLoadState = %v, want policyLoadReading", got.policyLoadState)
	}
	if cmd == nil {
		t.Fatal("enter path cmd = nil, want file read command")
	}

	msg := cmd()
	loadMsg, ok := msg.(PolicyLoadFileMsg)
	if !ok {
		t.Fatalf("read command message = %T, want PolicyLoadFileMsg", msg)
	}
	if loadMsg.Error != nil {
		t.Fatalf("PolicyLoadFileMsg error = %v", loadMsg.Error)
	}
	got, cmd = updateForTest(t, got, loadMsg)
	if cmd != nil {
		t.Fatalf("PolicyLoadFileMsg cmd = %v, want nil", cmd)
	}
	if got.policyLoadState != policyLoadConfirm || got.policyLoadYAML != yamlText || got.policyLoadBytes != len(yamlText) {
		t.Fatalf("policy load state = %v yaml %q bytes %d, want confirm", got.policyLoadState, got.policyLoadYAML, got.policyLoadBytes)
	}
	rendered := stripANSI(got.renderPolicyViewer())
	for _, want := range []string{"Load policy YAML", "This will replace policy.yaml as a whole file.", "max_fee_microalgos: 4321"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("renderPolicyViewer() missing %q:\n%s", want, rendered)
		}
	}
}

func TestPolicyViewerLoadConfirmStartsReplacement(t *testing.T) {
	m := Model{
		viewState:        ViewPolicyViewer,
		policyLoadState:  policyLoadConfirm,
		policyLoadYAML:   "max_fee_microalgos: 4321\n",
		policySnapshot:   &PolicySnapshot{Success: true, PolicySHA256: "abc123"},
		policyViewLoaded: true,
	}
	next, cmd := m.handlePolicyViewerKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	got := next.(Model)
	if got.policyLoadState != policyLoadReplacing {
		t.Fatalf("policyLoadState = %v, want policyLoadReplacing", got.policyLoadState)
	}
	if cmd == nil {
		t.Fatal("confirm cmd = nil, want replace command")
	}
}

func TestPolicyReplaceResultBuildsPolicyViewAndClearsLoadState(t *testing.T) {
	m := Model{
		viewState:       ViewPolicyViewer,
		policyLoadState: policyLoadReplacing,
		policyLoadPath:  "/tmp/policy.yaml",
	}
	next, cmd := updateForTest(t, m, PolicyReplaceResultMsg{Snapshot: PolicySnapshot{
		Success:      true,
		IdentityID:   "default",
		PolicyYAML:   "max_fee_microalgos: 4321\n",
		PolicySHA256: "def456",
		Canonical:    true,
	}})
	if cmd == nil {
		t.Fatal("PolicyReplaceResultMsg cmd = nil, want waitForMessageCmd")
	}
	if !next.policyViewLoaded || next.policyViewError != "" {
		t.Fatalf("policyViewLoaded = %v error %q, want loaded", next.policyViewLoaded, next.policyViewError)
	}
	if next.policyLoadState != policyLoadIdle || next.policyLoadYAML != "" {
		t.Fatalf("policy load state = %v yaml %q, want idle and cleared", next.policyLoadState, next.policyLoadYAML)
	}
	if !strings.Contains(next.policyLoadStatus, "Replaced policy from /tmp/policy.yaml") {
		t.Fatalf("policyLoadStatus = %q, want replacement status", next.policyLoadStatus)
	}
}

func TestRenderPolicyViewerYAMLModeShowsCanonicalYAML(t *testing.T) {
	m := Model{
		viewState:        ViewPolicyViewer,
		width:            100,
		height:           24,
		policyViewLoaded: true,
		policyViewMode:   policyViewerModeYAML,
		policyView: policyview.Model{
			YAML: "reject_foreign_rekey: true\ntransfer_policy:\n  schema_version: 1\n",
		},
	}

	rendered := stripANSI(m.renderPolicyViewer())
	for _, want := range []string{
		"3 YAML",
		"1  reject_foreign_rekey: true",
		"transfer_policy:",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("renderPolicyViewer() missing %q:\n%s", want, rendered)
		}
	}
}

func TestRenderPolicyViewerOverridesModeShowsOverrideDetails(t *testing.T) {
	rejectAssetClose := true
	maxFee := uint64(5000)
	enabled := true
	stored := &policy.StoredConfig{
		KeyOverrides: map[string]*policy.StoredConfig{
			types.Address{9}.String(): {
				RejectAssetClose: &rejectAssetClose,
				MaxFeeMicroAlgos: &maxFee,
				TransferPolicy: &policy.StoredTransferPolicy{
					SchemaVersion: 1,
					Enabled:       &enabled,
					Routes: []policy.StoredTransferRoute{
						{
							ID:           "falcon_algo",
							Networks:     []string{"mainnet"},
							Sources:      []string{"*"},
							Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
							Destinations: []string{"OPS..."},
						},
					},
				},
			},
		},
	}

	m := Model{
		viewState:        ViewPolicyViewer,
		width:            120,
		height:           30,
		policyViewLoaded: true,
		policyViewMode:   policyViewerModeOverrides,
		policyView:       policyview.Build(stored, ""),
	}

	rendered := stripANSI(m.renderPolicyViewer())
	for _, want := range []string{
		"Key overrides",
		types.Address{9}.String(),
		"Reject asset close",
		"Max fee microAlgos",
		"falcon",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("renderPolicyViewer() missing %q:\n%s", want, rendered)
		}
	}
}

func TestRenderPolicyViewerStaysWithinPane(t *testing.T) {
	for _, tt := range []struct {
		name string
		mode policyViewerMode
	}{
		{"overview", policyViewerModeOverview},
		{"guard detail", policyViewerModeGuardDetail},
		{"yaml", policyViewerModeYAML},
		{"overrides", policyViewerModeOverrides},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := policyViewerConstraintFixture()
			m.policyViewMode = tt.mode

			rendered := m.renderPolicyViewer()
			if lines, maxLines := visibleLineCount(rendered), m.policyViewerContentHeight(); lines > maxLines {
				t.Fatalf("policy viewer rendered %d lines, want <= %d:\n%s", lines, maxLines, stripANSI(rendered))
			}
			for i, line := range strings.Split(strings.TrimRight(rendered, "\n"), "\n") {
				if width := visibleWidth(line); width > m.width {
					t.Fatalf("policy viewer line %d width = %d, want <= %d\nline: %q\nview:\n%s",
						i+1, width, m.width, stripANSI(line), stripANSI(rendered))
				}
			}
		})
	}
}

func policyViewerConstraintFixture() Model {
	enabled := true
	reject := "reject"
	maxFee := uint64(5000)
	stored := &policy.StoredConfig{
		RejectForeignRekey: &enabled,
		MaxFeeMicroAlgos:   &maxFee,
		TransferPolicy: &policy.StoredTransferPolicy{
			SchemaVersion: 1,
			Enabled:       &enabled,
			OnNoRoute:     &reject,
			AssetSets: map[string]policy.StoredAssetSet{
				"stablecoin_with_a_long_display_name": {
					"mainnet": []uint64{31566704, 10458941, 123456789},
				},
			},
			Routes: []policy.StoredTransferRoute{
				{
					ID:          "route_algo_with_a_name_that_should_not_escape_the_panel",
					Description: "A deliberately long guard description that should be constrained by the policy viewer parent width",
					Networks:    []string{"mainnet", "testnet", "betanet"},
					Sources:     []string{"*"},
					Assets:      []policy.StoredAssetTerm{{Raw: "algo"}},
					Destinations: []string{
						"M75XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
						"JHXBYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
					},
				},
				{
					ID:          "route_usdc_with_a_name_that_should_not_escape_the_panel",
					Description: "A deliberately long guard description that should be constrained by the policy viewer parent width",
					Networks:    []string{"mainnet", "testnet", "betanet"},
					Sources:     []string{"*"},
					Assets:      []policy.StoredAssetTerm{{Raw: "@stablecoin_with_a_long_display_name"}},
					Destinations: []string{
						"M75XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
						"JHXBYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
					},
				},
			},
		},
		KeyOverrides: map[string]*policy.StoredConfig{
			types.Address{9}.String(): {
				RejectAssetClose: &enabled,
				TransferPolicy: &policy.StoredTransferPolicy{
					SchemaVersion: 1,
					Enabled:       &enabled,
					RoutesSet:     true,
					Routes: []policy.StoredTransferRoute{{
						ID:           "route_override_algo_with_a_long_name",
						Networks:     []string{"mainnet"},
						Sources:      []string{"*"},
						Assets:       []policy.StoredAssetTerm{{Raw: "algo"}},
						Destinations: []string{"M75XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
					}},
				},
			},
		},
	}

	return Model{
		viewState:        ViewPolicyViewer,
		width:            46,
		height:           14,
		policyViewLoaded: true,
		policySnapshot: &PolicySnapshot{
			IdentityID:   "identity-with-a-name-that-should-not-escape-the-parent-pane",
			PolicySHA256: strings.Repeat("0123456789abcdef", 4),
			Canonical:    true,
		},
		policyView: policyview.Build(stored, strings.Repeat(
			"very_long_policy_key_with_nested_value: very_long_policy_value_that_should_not_escape\n",
			30,
		)),
	}
}
