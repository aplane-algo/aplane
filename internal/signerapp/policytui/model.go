// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policytui provides the shared structured policy terminal UI.
package policytui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

type fieldKind int

const (
	fieldBool fieldKind = iota
	fieldReadonly
)

type screen int

const (
	screenHome screen = iota
	screenRoutes
	screenBlockedDestinationsEdit
	screenRouteYAML
	screenAssetSets
	screenAssetSetEdit
	screenAssetSetTextEdit
	screenRouteEdit
	screenRouteListEdit
	screenRouteTextEdit
	screenRouteChoiceEdit
	screenTransferSettings
	screenTransferSettingsChoiceEdit
	screenApplyPassphrase
	screenWriteFile
	screenQuitConfirm
	screenDeleteRouteConfirm
	screenDeleteAssetSetConfirm
)

const (
	modifiedProductionWarning = "draft differs from production; q can quit without applying to production"
	modifiedDraftWarning      = "draft has unsaved changes; q can quit without saving the draft"
)

type field struct {
	key    string
	label  string
	kind   fieldKind
	value  func(*policy.StoredConfig) string
	source func(*policy.StoredConfig) string
	cycle  func(*policy.StoredConfig)
}

// Model is the shared policy editor Bubble Tea model.
type Model struct {
	store                     policyeditor.Store
	persistence               policyeditor.Persistence
	target                    policyeditor.Target
	policy                    *policy.StoredConfig
	baseline                  []byte
	dataDir                   string
	identityID                string
	screen                    screen
	cursor                    int
	routeCursor               int
	assetSetCursor            int
	editRouteIndex            int
	editGroupIndex            int
	editCursor                int
	editFields                []routeEditField
	editAssetRows             []routeEditAssetRow
	blockedDestinationsFields []routeEditField
	editListOffset            int
	editChoiceCursor          int
	settingsCursor            int
	settingsFields            []routeEditField
	editAssetSetIndex         int
	editAssetSetOriginalName  string
	editAssetSetName          string
	editAssetSetRows          []assetSetEditRow
	routeYAMLOffset           int
	previousScreen            screen
	quitAfterPersist          bool
	writePath                 string
	applyPassphrase           []rune
	deleteRouteIndex          int
	deleteAssetSetName        string
	formApplyToken            uint64
	width                     int
	height                    int
	busy                      bool
	status                    string
	err                       string
	fields                    []field
}

type persistenceResultMsg struct {
	baseline []byte
	err      error
}

type writeFileResultMsg struct {
	path string
	err  error
}

type validateResultMsg struct {
	err error
}

type routeApplyResultMsg struct {
	token      uint64
	groupIndex int
	routes     []policy.StoredTransferRoute
	err        error
}

type transferSettingsApplyResultMsg struct {
	token  uint64
	policy *policy.StoredTransferPolicy
	err    error
}

type blockedDestinationsApplyResultMsg struct {
	token        uint64
	destinations []string
	err          error
}

type assetSetApplyResultMsg struct {
	token   uint64
	oldName string
	name    string
	set     policy.StoredAssetSet
	err     error
}

type assetSetDeleteResultMsg struct {
	token uint64
	name  string
	err   error
}

type routeEditField struct {
	key   string
	label string
	value string
}

// New returns a policy editor model initialized with a verified signer policy.
// NewWithTarget returns a policy editor model initialized with a verified stored
// policy document for the selected domain.
func NewWithTarget(store policyeditor.Store, stored *policy.StoredConfig, dataDir, identityID string, target policyeditor.Target) Model {
	if target == "" || target == policyeditor.TargetAuto {
		target = policyeditor.TargetSigner
	}
	cp, baseline, err := cloneStoredForTarget(stored, target)
	m := Model{
		store:       store,
		persistence: store.Persistence(),
		target:      target,
		policy:      cp,
		baseline:    baseline,
		dataDir:     dataDir,
		identityID:  identityID,
		status:      fmt.Sprintf("loaded verified %s", target.StatusNoun()),
		fields:      policyFieldsForTarget(target),
	}
	if err != nil {
		m.err = err.Error()
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		switch m.screen {
		case screenRoutes:
			return m.handleRouteKey(msg)
		case screenBlockedDestinationsEdit:
			return m.handleBlockedDestinationsEditKey(msg)
		case screenRouteYAML:
			return m.handleRouteYAMLKey(msg)
		case screenAssetSets:
			return m.handleAssetSetKey(msg)
		case screenAssetSetEdit:
			return m.handleAssetSetEditKey(msg)
		case screenAssetSetTextEdit:
			return m.handleAssetSetTextEditKey(msg)
		case screenRouteEdit:
			return m.handleRouteEditKey(msg)
		case screenRouteListEdit:
			return m.handleRouteListEditKey(msg)
		case screenRouteTextEdit:
			return m.handleRouteTextEditKey(msg)
		case screenRouteChoiceEdit:
			return m.handleRouteChoiceEditKey(msg)
		case screenTransferSettings:
			return m.handleTransferSettingsKey(msg)
		case screenTransferSettingsChoiceEdit:
			return m.handleTransferSettingsChoiceEditKey(msg)
		case screenApplyPassphrase:
			return m.handleApplyPassphraseKey(msg)
		case screenWriteFile:
			return m.handleWriteFileKey(msg)
		case screenQuitConfirm:
			return m.handleQuitConfirmKey(msg)
		case screenDeleteRouteConfirm:
			return m.handleDeleteRouteConfirmKey(msg)
		case screenDeleteAssetSetConfirm:
			return m.handleDeleteAssetSetConfirmKey(msg)
		default:
			return m.handleHomeKey(msg)
		}
	case persistenceResultMsg:
		m.busy = false
		if msg.err != nil {
			if clearer, ok := m.store.(productionPassphraseClearer); ok {
				clearer.ClearPassphrase()
			}
			m.err = msg.err.Error()
			m.status = m.persistenceFailedStatus()
			m.quitAfterPersist = false
			return m, nil
		}
		m.baseline = msg.baseline
		m.err = ""
		m.status = m.persistenceSuccessStatus()
		if m.quitAfterPersist {
			return m, tea.Quit
		}
		return m, nil
	case writeFileResultMsg:
		m.busy = false
		if msg.err != nil {
			m.err = msg.err.Error()
			m.status = "write failed"
			return m, nil
		}
		m.screen = m.previousScreen
		m.writePath = ""
		m.err = ""
		m.status = fmt.Sprintf("wrote %s draft to %s", m.target.StatusNoun(), msg.path)
		return m, nil
	case validateResultMsg:
		m.busy = false
		if msg.err != nil {
			m.err = friendlyPolicyError(msg.err)
			m.status = "validation failed"
			return m, nil
		}
		m.err = ""
		m.status = fmt.Sprintf("%s validates", m.target.StatusNoun())
		return m, nil
	case routeApplyResultMsg:
		if msg.token != m.formApplyToken {
			return m, nil
		}
		m.busy = false
		if msg.err != nil {
			m.err = friendlyPolicyError(msg.err)
			m.status = "guard validation failed"
			return m, nil
		}
		if m.policy == nil || m.policy.TransferPolicy == nil {
			m.ensureTransferPolicy()
		}
		groups := transferGuardGroups(m.policy.TransferPolicy.Routes)
		if msg.groupIndex < 0 || msg.groupIndex >= len(groups) {
			m.err = "route index is no longer valid"
			m.status = "guard save failed"
			return m, nil
		}
		start, end := guardGroupRouteRange(groups[msg.groupIndex])
		updated := removeRouteBlock(m.policy.TransferPolicy.Routes, start, end)
		m.policy.TransferPolicy.Routes = insertRoutes(updated, start, msg.routes)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor = msg.groupIndex
		m.err = ""
		if m.screen == screenRouteEdit {
			updatedGroups := transferGuardGroups(m.policy.TransferPolicy.Routes)
			if msg.groupIndex >= 0 && msg.groupIndex < len(updatedGroups) {
				m.editFields = m.guardGroupToEditFields(updatedGroups[msg.groupIndex])
				m.editAssetRows = m.guardGroupToEditAssetRows(updatedGroups[msg.groupIndex])
				if m.editCursor >= m.routeEditItemCount() {
					m.editCursor = m.routeEditItemCount() - 1
				}
			}
			m.status = "saved guard"
		} else {
			m.screen = screenRoutes
			m.status = "updated guard"
		}
		return m, nil
	case transferSettingsApplyResultMsg:
		if msg.token != m.formApplyToken {
			return m, nil
		}
		m.busy = false
		if msg.err != nil {
			m.err = friendlyPolicyError(msg.err)
			m.status = "transfer settings validation failed"
			return m, nil
		}
		if m.policy == nil {
			m.policy = &policy.StoredConfig{}
		}
		m.policy.TransferPolicy = msg.policy
		m.err = ""
		if m.screen == screenTransferSettings {
			m.settingsFields = transferSettingsToFields(msg.policy)
			if m.settingsCursor >= len(m.settingsFields) {
				m.settingsCursor = len(m.settingsFields) - 1
			}
			m.status = "saved transfer policy settings"
		} else {
			m.screen = screenRoutes
			m.status = "updated transfer policy settings"
		}
		return m, nil
	case blockedDestinationsApplyResultMsg:
		if msg.token != m.formApplyToken {
			return m, nil
		}
		m.busy = false
		if msg.err != nil {
			m.err = friendlyPolicyError(msg.err)
			m.status = "blocked destinations validation failed"
			return m, nil
		}
		if m.policy == nil {
			m.policy = &policy.StoredConfig{}
		}
		if m.policy.TransferPolicy == nil {
			m.policy.TransferPolicy = m.defaultBlockedDestinationsTransferPolicy()
		}
		m.policy.TransferPolicy.BlockedDestinations = append([]string(nil), msg.destinations...)
		m.screen = screenRoutes
		m.err = ""
		m.status = "updated blocked destinations"
		return m, nil
	case assetSetApplyResultMsg:
		if msg.token != m.formApplyToken {
			return m, nil
		}
		m.busy = false
		if msg.err != nil {
			m.err = friendlyPolicyError(msg.err)
			m.status = "asset set validation failed"
			return m, nil
		}
		if m.policy == nil || m.policy.TransferPolicy == nil {
			m.ensureTransferPolicy()
		}
		if m.policy.TransferPolicy.AssetSets == nil {
			m.policy.TransferPolicy.AssetSets = make(map[string]policy.StoredAssetSet)
		}
		if msg.oldName != "" && msg.oldName != msg.name {
			delete(m.policy.TransferPolicy.AssetSets, msg.oldName)
		}
		m.policy.TransferPolicy.AssetSets[msg.name] = cloneAssetSet(msg.set)
		m.assetSetCursor = assetSetIndexByName(m.assetSetRows(), msg.name)
		m.editAssetSetOriginalName = msg.name
		m.err = ""
		if m.screen == screenAssetSetEdit {
			m.status = fmt.Sprintf("saved asset set %s", msg.name)
		} else {
			m.screen = screenAssetSets
			m.status = fmt.Sprintf("updated asset set %s", msg.name)
		}
		return m, nil
	case assetSetDeleteResultMsg:
		if msg.token != m.formApplyToken {
			return m, nil
		}
		m.busy = false
		if msg.err != nil {
			m.err = friendlyPolicyError(msg.err)
			m.status = "asset set delete failed"
			m.screen = screenAssetSets
			return m, nil
		}
		if m.policy != nil && m.policy.TransferPolicy != nil {
			delete(m.policy.TransferPolicy.AssetSets, msg.name)
			if len(m.policy.TransferPolicy.AssetSets) == 0 {
				m.policy.TransferPolicy.AssetSets = nil
			}
		}
		if m.assetSetCursor >= len(m.assetSetRows()) && m.assetSetCursor > 0 {
			m.assetSetCursor--
		}
		m.screen = screenAssetSets
		m.err = ""
		m.status = fmt.Sprintf("deleted asset set %s", msg.name)
		return m, nil
	default:
		return m, nil
	}
}

func (m Model) View() string {
	body := m.bodyView()
	width := m.panelWidth()
	return panelStyle.Width(width).Render(body)
}

func (m Model) bodyView() string {
	var b strings.Builder
	state := "clean"
	if m.modified() {
		state = "modified"
	}
	b.WriteString(titleStyle.Render("APlane " + m.target.Label()))
	b.WriteString("\n")
	mode := "offline"
	if labeler, ok := m.store.(storeModeLabeler); ok {
		if label := strings.TrimSpace(labeler.ModeLabel()); label != "" {
			mode = label
		}
	}
	b.WriteString(subtitleStyle.Render(mode + " " + m.target.StatusNoun() + " editor"))
	b.WriteString("\n\n")
	b.WriteString(metadataStyle.Render(fmt.Sprintf("store: %s", m.dataDir)))
	b.WriteString("\n")
	b.WriteString(metadataStyle.Render(fmt.Sprintf("identity: %s", m.identityID)))
	b.WriteString("\n")
	b.WriteString(metadataStyle.Render(fmt.Sprintf("document: %s", m.target.DocumentName())))
	b.WriteString("\n")
	b.WriteString(metadataStyle.Render("state: "))
	b.WriteString(stateStyle(state).Render(state))
	b.WriteString("\n")
	if m.status != "" {
		b.WriteString(metadataStyle.Render("status: "))
		b.WriteString(statusStyle(m).Render(m.status))
		b.WriteString("\n")
	}
	if m.err != "" {
		b.WriteString(statusErrorStyle.Render("error: " + m.err))
		b.WriteString("\n")
	}
	if m.busy {
		b.WriteString(statusWarnStyle.Render("working..."))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if m.screen == screenRoutes {
		b.WriteString(m.routeView())
		return b.String()
	}
	if m.screen == screenBlockedDestinationsEdit {
		b.WriteString(m.blockedDestinationsEditView())
		return b.String()
	}
	if m.screen == screenRouteYAML {
		b.WriteString(m.routeYAMLView())
		return b.String()
	}
	if m.screen == screenAssetSets {
		b.WriteString(m.assetSetView())
		return b.String()
	}
	if m.screen == screenAssetSetEdit {
		b.WriteString(m.assetSetEditView())
		return b.String()
	}
	if m.screen == screenAssetSetTextEdit {
		b.WriteString(m.assetSetTextEditView())
		return b.String()
	}
	if m.screen == screenRouteEdit {
		b.WriteString(m.routeEditView())
		return b.String()
	}
	if m.screen == screenRouteListEdit {
		b.WriteString(m.routeListEditView())
		return b.String()
	}
	if m.screen == screenRouteTextEdit {
		b.WriteString(m.routeTextEditView())
		return b.String()
	}
	if m.screen == screenRouteChoiceEdit {
		b.WriteString(m.routeChoiceEditView())
		return b.String()
	}
	if m.screen == screenTransferSettings {
		b.WriteString(m.transferSettingsView())
		return b.String()
	}
	if m.screen == screenTransferSettingsChoiceEdit {
		b.WriteString(m.transferSettingsChoiceEditView())
		return b.String()
	}
	if m.screen == screenApplyPassphrase {
		b.WriteString(m.applyPassphraseView())
		return b.String()
	}
	if m.screen == screenWriteFile {
		b.WriteString(m.writeFileView())
		return b.String()
	}
	if m.screen == screenQuitConfirm {
		b.WriteString(m.quitConfirmView())
		return b.String()
	}
	if m.screen == screenDeleteRouteConfirm {
		b.WriteString(m.deleteRouteConfirmView())
		return b.String()
	}
	if m.screen == screenDeleteAssetSetConfirm {
		b.WriteString(m.deleteAssetSetConfirmView())
		return b.String()
	}

	b.WriteString(sectionStyle.Render("Policy Fields"))
	b.WriteString("\n\n")
	b.WriteString(metadataStyle.Render(
		"  " +
			fixedWidthFieldLine("Setting", policyFieldLabelWidth) + " " +
			fixedWidthFieldLine("Value", policyFieldValueWidth) + " " +
			"Source",
	))
	b.WriteString("\n")
	for i, field := range m.fields {
		b.WriteString(m.renderFieldRow(i, field))
		b.WriteString("\n")
	}

	b.WriteString("\nkeys: up/down move  space/enter cycle  v validate  w write draft  a " + m.persistenceKeyLabel() + "  q quit\n")
	if m.modified() {
		b.WriteString(m.modifiedWarning() + "\n")
	}
	return m.renderHelp(b.String())
}
