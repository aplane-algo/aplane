// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policytui provides the standalone appolicy terminal UI.
package policytui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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

const modifiedProductionWarning = "draft differs from production; q can quit without applying to production"

type field struct {
	key    string
	label  string
	kind   fieldKind
	value  func(*policy.StoredConfig) string
	source func(*policy.StoredConfig) string
	cycle  func(*policy.StoredConfig)
}

// Model is the appolicy Bubble Tea model.
type Model struct {
	store                     policyeditor.Store
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
	quitAfterApply            bool
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

type productionApplyResultMsg struct {
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

type productionPassphraseStore interface {
	RequiresPassphraseForSave() bool
	SetPassphrase([]byte)
}

type productionPassphraseClearer interface {
	ClearPassphrase()
}

type storeModeLabeler interface {
	ModeLabel() string
}

type routeEditField struct {
	key   string
	label string
	value string
}

type routeEditAssetRow struct {
	routeIndex  int
	routeID     string
	asset       string
	reviewAbove string
	rejectAbove string
}

const routeEditAssetColumnCount = 3
const policyFieldLabelWidth = 36
const policyFieldValueWidth = 34

// New returns an appolicy model initialized with a verified signer policy.
func New(store policyeditor.Store, stored *policy.StoredConfig, dataDir, identityID string) Model {
	return NewWithTarget(store, stored, dataDir, identityID, policyeditor.TargetSigner)
}

// NewWithTarget returns an appolicy model initialized with a verified stored
// policy document for the selected domain.
func NewWithTarget(store policyeditor.Store, stored *policy.StoredConfig, dataDir, identityID string, target policyeditor.Target) Model {
	if target == "" || target == policyeditor.TargetAuto {
		target = policyeditor.TargetSigner
	}
	cp, baseline, err := cloneStoredForTarget(stored, target)
	m := Model{
		store:      store,
		target:     target,
		policy:     cp,
		baseline:   baseline,
		dataDir:    dataDir,
		identityID: identityID,
		status:     fmt.Sprintf("loaded verified %s", target.StatusNoun()),
		fields:     policyFieldsForTarget(target),
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
	case productionApplyResultMsg:
		m.busy = false
		if msg.err != nil {
			if clearer, ok := m.store.(productionPassphraseClearer); ok {
				clearer.ClearPassphrase()
			}
			m.err = msg.err.Error()
			m.status = "apply failed"
			m.quitAfterApply = false
			return m, nil
		}
		m.baseline = msg.baseline
		m.err = ""
		m.status = fmt.Sprintf("applied %s and %s", m.target.DocumentName(), m.target.SidecarName())
		if m.quitAfterApply {
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

func (m Model) handleHomeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc", "q":
		return m.requestQuit()
	}
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.fields)-1 {
			m.cursor++
		}
	case " ", "enter":
		current := m.fields[m.cursor]
		if current.key == "transfer_policy" {
			m.screen = screenRoutes
			m.status = "guard list"
			m.err = ""
			return m, nil
		}
		if current.kind != fieldBool {
			m.status = "selected field is read-only in this slice"
			return m, nil
		}
		current.cycle(m.policy)
		m.err = ""
		m.status = fmt.Sprintf("changed %s to %s", current.key, current.value(m.policy))
	case "a":
		return m.applyProduction()
	case "w":
		return m.openWriteFile()
	case "v":
		return m.validate()
	}
	return m, nil
}

func (m Model) handleRouteKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m.requestQuit()
	case "esc", "backspace":
		m.screen = screenHome
		m.status = fmt.Sprintf("%s fields", strings.ToLower(m.target.Label()))
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	routes := m.routes()
	groups := transferGuardGroups(routes)
	switch msg.String() {
	case "up", "k":
		if m.routeCursor > 0 {
			m.routeCursor--
		}
	case "down", "j":
		if m.routeCursor < len(groups)-1 {
			m.routeCursor++
		}
	case "enter", "e":
		if len(groups) == 0 {
			m.status = "no guards to edit"
			return m, nil
		}
		return m.openGuardGroupEditor(groups[m.routeCursor]), nil
	case " ":
		if len(groups) == 0 {
			m.status = "no guards to edit"
			return m, nil
		}
		group := groups[m.routeCursor]
		m.cycleSelectedGuardGroupEnabled(group)
		m.status = fmt.Sprintf("changed guard %s enabled to %s", group.ID, boolValueWithDefault(m.selectedGuardGroupEnabled(group), true))
		m.err = ""
	case "n":
		m.enableTransferPolicyForGuards()
		route := m.newRoute()
		m.policy.TransferPolicy.Routes = append(m.policy.TransferPolicy.Routes, route)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor = len(transferGuardGroups(m.policy.TransferPolicy.Routes)) - 1
		m.status = fmt.Sprintf("added guard %s", guardNameFromRoute(route.ID, route.Assets[0].Raw))
		m.err = ""
	case "c":
		if len(groups) == 0 {
			m.status = "no guard to clone"
			return m, nil
		}
		group := groups[m.routeCursor]
		clones := m.cloneGuardGroup(group)
		_, end := guardGroupRouteRange(group)
		m.policy.TransferPolicy.Routes = insertRoutes(m.policy.TransferPolicy.Routes, end, clones)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor++
		m.status = fmt.Sprintf("cloned guard %s", group.ID)
		m.err = ""
	case "d":
		if len(groups) == 0 {
			m.status = "no guard to delete"
			return m, nil
		}
		m.screen = screenDeleteRouteConfirm
		m.deleteRouteIndex = m.routeCursor
		m.status = fmt.Sprintf("confirm delete guard %s", groups[m.routeCursor].ID)
		m.err = ""
	case "b":
		return m.openBlockedDestinationsEditor(), nil
	case "u":
		if m.routeCursor <= 0 || len(groups) == 0 {
			return m, nil
		}
		m.policy.TransferPolicy.Routes = moveGuardGroupUp(routes, groups, m.routeCursor)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor--
		m.status = "moved guard up"
		m.err = ""
	case "U":
		if m.routeCursor >= len(groups)-1 || len(groups) == 0 {
			return m, nil
		}
		m.policy.TransferPolicy.Routes = moveGuardGroupDown(routes, groups, m.routeCursor)
		m.policy.TransferPolicy.RoutesSet = true
		m.routeCursor++
		m.status = "moved guard down"
		m.err = ""
	case "p":
		m.ensureTransferPolicy()
		return m.openTransferSettings(), nil
	case "t", "T":
		return m.openAssetSets(), nil
	case "y", "Y":
		m.screen = screenRouteYAML
		m.routeYAMLOffset = 0
		m.status = "transfer policy yaml"
		m.err = ""
	case "a":
		return m.applyProduction()
	case "w":
		return m.openWriteFile()
	case "v":
		return m.validate()
	}
	return m, nil
}

func (m Model) handleRouteYAMLKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m.requestQuit()
	case "esc", "b", "backspace":
		m.screen = screenRoutes
		m.routeYAMLOffset = 0
		m.status = "guard list"
		m.err = ""
		return m, nil
	case "up", "k":
		if m.routeYAMLOffset > 0 {
			m.routeYAMLOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := m.routeYAMLMaxOffset()
		if m.routeYAMLOffset < maxOffset {
			m.routeYAMLOffset++
		}
		return m, nil
	case "pgup":
		m.routeYAMLOffset -= m.routeYAMLVisibleLines()
		if m.routeYAMLOffset < 0 {
			m.routeYAMLOffset = 0
		}
		return m, nil
	case "pgdown":
		maxOffset := m.routeYAMLMaxOffset()
		m.routeYAMLOffset += m.routeYAMLVisibleLines()
		if m.routeYAMLOffset > maxOffset {
			m.routeYAMLOffset = maxOffset
		}
		return m, nil
	case "a":
		return m.applyProduction()
	case "w":
		return m.openWriteFile()
	}
	return m, nil
}

func (m Model) handleAssetSetKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m.requestQuit()
	case "esc", "b", "backspace":
		m.screen = screenRoutes
		m.status = "guard list"
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	rows := m.assetSetRows()
	switch msg.String() {
	case "up", "k":
		if m.assetSetCursor > 0 {
			m.assetSetCursor--
		}
	case "down", "j":
		if m.assetSetCursor < len(rows)-1 {
			m.assetSetCursor++
		}
	case "enter", "e":
		if len(rows) == 0 {
			m.status = "no asset sets to edit"
			return m, nil
		}
		return m.openAssetSetEditor(rows[m.assetSetCursor]), nil
	case "n":
		return m.openNewAssetSetEditor(), nil
	case "c":
		if len(rows) == 0 {
			m.status = "no asset set to clone"
			return m, nil
		}
		return m.openClonedAssetSetEditor(rows[m.assetSetCursor]), nil
	case "d", "x":
		if len(rows) == 0 {
			m.status = "no asset set to delete"
			return m, nil
		}
		m.screen = screenDeleteAssetSetConfirm
		m.deleteAssetSetName = rows[m.assetSetCursor].Name
		m.status = fmt.Sprintf("confirm delete asset set %s", m.deleteAssetSetName)
		m.err = ""
	case "y", "Y":
		m.screen = screenRouteYAML
		m.routeYAMLOffset = 0
		m.status = "transfer policy yaml"
		m.err = ""
	case "a":
		return m.applyProduction()
	case "w":
		return m.openWriteFile()
	case "v":
		return m.validate()
	}
	return m, nil
}

func (m Model) handleAssetSetEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "b", "backspace":
		if m.busy {
			m.cancelFormApply()
		}
		m.screen = screenAssetSets
		m.status = "asset sets"
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "up", "k":
		m.moveAssetSetEditCursor(-1)
	case "down", "j":
		m.moveAssetSetEditCursor(1)
	case "left", "h":
		m.moveAssetSetEditCursor(-1)
	case "right", "l", "tab":
		m.moveAssetSetEditCursor(1)
	case "enter", "e":
		return m.openAssetSetFieldEditor(), nil
	case "n":
		m.addAssetSetNetworkRow()
	case "x", "delete":
		before := len(m.editAssetSetRows)
		m.deleteCurrentAssetSetNetworkRow()
		if len(m.editAssetSetRows) == before {
			return m, nil
		}
		return m.applyAssetSetEdit()
	}
	return m, nil
}

func (m Model) handleAssetSetTextEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "enter":
		m.screen = screenAssetSetEdit
		m.err = ""
		return m.applyAssetSetEdit()
	}
	switch msg.Type {
	case tea.KeyBackspace, tea.KeyDelete:
		m.backspaceAssetSetTextInput()
	case tea.KeyCtrlU:
		m.setCurrentAssetSetEditValue("")
	case tea.KeyRunes:
		m.appendAssetSetTextInput(string(msg.Runes))
	}
	return m, nil
}

func (m Model) handleTransferSettingsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc":
		if m.busy {
			m.cancelFormApply()
		}
		m.screen = screenRoutes
		m.status = "guard list"
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	switch msg.Type {
	case tea.KeyUp:
		if m.settingsCursor > 0 {
			m.settingsCursor--
		}
	case tea.KeyDown, tea.KeyTab:
		if m.settingsCursor < len(m.settingsFields)-1 {
			m.settingsCursor++
		}
	case tea.KeyShiftTab:
		if m.settingsCursor > 0 {
			m.settingsCursor--
		}
	case tea.KeyBackspace, tea.KeyDelete:
		m.status = "press enter to edit this field"
	case tea.KeyCtrlU:
		m.status = "press enter to edit this field"
	case tea.KeyEnter:
		return m.openTransferSettingsFieldEditor(), nil
	case tea.KeyRunes:
		m.status = "press enter to edit this field"
	}
	return m, nil
}

func (m Model) handleBlockedDestinationsEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "b":
		if m.busy {
			m.cancelFormApply()
			m.screen = screenRoutes
			m.editListOffset = 0
			m.status = "guard list"
			m.err = ""
			return m, nil
		}
		m.editListOffset = 0
		return m.applyBlockedDestinationsEdit()
	}
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "up", "k":
		if m.editListOffset > 0 {
			m.editListOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := m.routeListMaxOffset()
		if m.editListOffset < maxOffset {
			m.editListOffset++
		}
		return m, nil
	case "pgup":
		m.editListOffset -= m.routeListVisibleLines()
		if m.editListOffset < 0 {
			m.editListOffset = 0
		}
		return m, nil
	case "pgdown":
		maxOffset := m.routeListMaxOffset()
		m.editListOffset += m.routeListVisibleLines()
		if m.editListOffset > maxOffset {
			m.editListOffset = maxOffset
		}
		return m, nil
	case "home":
		m.editListOffset = 0
		return m, nil
	case "end":
		m.editListOffset = m.routeListMaxOffset()
		return m, nil
	}

	switch msg.Type {
	case tea.KeyBackspace, tea.KeyDelete:
		m.backspaceRouteListInput()
	case tea.KeyCtrlU:
		m.clearRouteListInput()
	case tea.KeyEnter:
		m.appendRouteListInput("\n")
	case tea.KeyRunes:
		m.appendRouteListInput(string(msg.Runes))
	}
	return m, nil
}

func (m Model) handleTransferSettingsChoiceEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.currentSettingsKey()
	choices := transferSettingsChoiceOptionsForKey(key)
	if len(choices) == 0 {
		m.screen = screenTransferSettings
		m.status = "transfer policy settings"
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "b":
		m.screen = screenTransferSettings
		m.status = "transfer policy settings"
		m.err = ""
		return m, nil
	case "up", "k":
		if m.editChoiceCursor > 0 {
			m.editChoiceCursor--
		}
		return m, nil
	case "down", "j", "tab":
		if m.editChoiceCursor < len(choices)-1 {
			m.editChoiceCursor++
		}
		return m, nil
	case "home":
		m.editChoiceCursor = 0
		return m, nil
	case "end":
		m.editChoiceCursor = len(choices) - 1
		return m, nil
	case "enter", " ", "space":
		m.setCurrentSettingsValue(choices[m.editChoiceCursor])
		m.screen = screenTransferSettings
		m.err = ""
		return m.applyTransferSettings()
	}
	return m, nil
}

func (m Model) handleRouteEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc":
		if m.busy {
			m.cancelFormApply()
		}
		m.screen = screenRoutes
		m.status = "guard list"
		m.err = ""
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "n":
		m.addEditAssetRow()
		return m, nil
	case "x", "d":
		before := len(m.editAssetRows)
		m.deleteCurrentEditAssetRow()
		if len(m.editAssetRows) == before {
			return m, nil
		}
		return m.applyRouteEdit()
	}
	switch msg.Type {
	case tea.KeyUp:
		if m.editCursor > 0 {
			m.editCursor--
		}
	case tea.KeyDown, tea.KeyTab, tea.KeyRight:
		if m.editCursor < m.routeEditItemCount()-1 {
			m.editCursor++
		}
	case tea.KeyLeft, tea.KeyShiftTab:
		if m.editCursor > 0 {
			m.editCursor--
		}
	case tea.KeyBackspace, tea.KeyDelete:
		m.status = "press enter to edit this field"
	case tea.KeyCtrlU:
		m.status = "press enter to edit this field"
	case tea.KeyEnter:
		return m.openRouteFieldEditor(), nil
	case tea.KeyRunes:
		m.status = "press enter to edit this field"
	}
	return m, nil
}

func (m Model) handleRouteListEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "b":
		m.screen = screenRouteEdit
		m.editListOffset = 0
		m.err = ""
		return m.applyRouteEdit()
	case "up", "k":
		if m.editListOffset > 0 {
			m.editListOffset--
		}
		return m, nil
	case "down", "j":
		maxOffset := m.routeListMaxOffset()
		if m.editListOffset < maxOffset {
			m.editListOffset++
		}
		return m, nil
	case "pgup":
		m.editListOffset -= m.routeListVisibleLines()
		if m.editListOffset < 0 {
			m.editListOffset = 0
		}
		return m, nil
	case "pgdown":
		maxOffset := m.routeListMaxOffset()
		m.editListOffset += m.routeListVisibleLines()
		if m.editListOffset > maxOffset {
			m.editListOffset = maxOffset
		}
		return m, nil
	case "home":
		m.editListOffset = 0
		return m, nil
	case "end":
		m.editListOffset = m.routeListMaxOffset()
		return m, nil
	}

	switch msg.Type {
	case tea.KeyBackspace, tea.KeyDelete:
		m.backspaceRouteListInput()
	case tea.KeyCtrlU:
		m.clearRouteListInput()
	case tea.KeyEnter:
		m.appendRouteListInput("\n")
	case tea.KeyRunes:
		m.appendRouteListInput(string(msg.Runes))
	}
	return m, nil
}

func (m Model) handleRouteTextEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "enter":
		m.screen = screenRouteEdit
		m.err = ""
		return m.applyRouteEdit()
	}
	switch msg.Type {
	case tea.KeyBackspace, tea.KeyDelete:
		m.backspaceEditField()
	case tea.KeyCtrlU:
		m.clearEditField()
	case tea.KeySpace:
		m.appendRouteTextInput(" ")
	case tea.KeyRunes:
		m.appendRouteTextInput(string(msg.Runes))
	}
	return m, nil
}

func (m Model) handleRouteChoiceEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.currentEditKey()
	choices := routeChoiceOptionsForKey(key)
	if len(choices) == 0 {
		m.screen = screenRouteEdit
		m.status = "guard edit"
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "esc", "b":
		m.screen = screenRouteEdit
		m.status = "guard edit"
		m.err = ""
		return m, nil
	case "up", "k":
		if m.editChoiceCursor > 0 {
			m.editChoiceCursor--
		}
		return m, nil
	case "down", "j", "tab":
		if m.editChoiceCursor < len(choices)-1 {
			m.editChoiceCursor++
		}
		return m, nil
	case "home":
		m.editChoiceCursor = 0
		return m, nil
	case "end":
		m.editChoiceCursor = len(choices) - 1
		return m, nil
	case "enter", " ", "space":
		m.setCurrentEditValue(choices[m.editChoiceCursor])
		m.screen = screenRouteEdit
		m.err = ""
		return m.applyRouteEdit()
	}
	return m, nil
}

func (m Model) handleQuitConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "q", "y", "ctrl+c":
		return m, tea.Quit
	case "a":
		m.quitAfterApply = true
		return m.applyProduction()
	case "esc", "n", "b", "backspace":
		m.screen = m.previousScreen
		m.quitAfterApply = false
		m.status = "exit canceled"
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) handleApplyPassphraseKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	if msg.String() == "ctrl+c" {
		m.clearApplyPassphrase()
		return m.requestQuit()
	}
	switch msg.Type {
	case tea.KeyEsc:
		m.clearApplyPassphrase()
		m.screen = m.previousScreen
		m.quitAfterApply = false
		m.status = "apply canceled"
		m.err = ""
		return m, nil
	case tea.KeyEnter:
		return m.submitApplyPassphrase()
	case tea.KeyBackspace, tea.KeyDelete, tea.KeyCtrlH:
		if len(m.applyPassphrase) > 0 {
			m.applyPassphrase[len(m.applyPassphrase)-1] = 0
			m.applyPassphrase = m.applyPassphrase[:len(m.applyPassphrase)-1]
		}
		m.err = ""
		return m, nil
	case tea.KeyCtrlU:
		m.clearApplyPassphrase()
		m.err = ""
		return m, nil
	case tea.KeySpace:
		m.applyPassphrase = append(m.applyPassphrase, ' ')
		m.err = ""
		return m, nil
	case tea.KeyRunes:
		m.applyPassphrase = append(m.applyPassphrase, msg.Runes...)
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) handleWriteFileKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	if msg.String() == "ctrl+c" {
		return m.requestQuit()
	}
	switch msg.Type {
	case tea.KeyEsc:
		m.screen = m.previousScreen
		m.writePath = ""
		m.status = "write canceled"
		m.err = ""
		return m, nil
	case tea.KeyEnter:
		return m.writeDraftFile()
	case tea.KeyBackspace, tea.KeyDelete, tea.KeyCtrlH:
		if m.writePath != "" {
			runes := []rune(m.writePath)
			m.writePath = string(runes[:len(runes)-1])
		}
		m.err = ""
		return m, nil
	case tea.KeyCtrlU:
		m.writePath = ""
		m.err = ""
		return m, nil
	case tea.KeySpace:
		m.writePath += " "
		m.err = ""
		return m, nil
	case tea.KeyRunes:
		m.writePath += string(msg.Runes)
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) handleDeleteRouteConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "y", "d":
		return m.deleteSelectedRouteConfirmed(), nil
	case "n", "esc", "b", "backspace":
		m.screen = screenRoutes
		m.status = "delete canceled"
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) handleDeleteAssetSetConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		return m.requestQuit()
	case "y", "d":
		return m.deleteSelectedAssetSetConfirmed()
	case "n", "esc", "b", "backspace":
		m.screen = screenAssetSets
		m.status = "delete canceled"
		m.err = ""
		return m, nil
	}
	return m, nil
}

func (m Model) deleteSelectedRouteConfirmed() Model {
	groups := transferGuardGroups(m.routes())
	if m.deleteRouteIndex < 0 || m.deleteRouteIndex >= len(groups) {
		m.screen = screenRoutes
		m.status = "guard no longer exists"
		return m
	}
	group := groups[m.deleteRouteIndex]
	deleted := group.ID
	start, end := guardGroupRouteRange(group)
	m.policy.TransferPolicy.Routes = removeRouteBlock(m.policy.TransferPolicy.Routes, start, end)
	m.policy.TransferPolicy.RoutesSet = true
	if m.routeCursor >= len(transferGuardGroups(m.policy.TransferPolicy.Routes)) && m.routeCursor > 0 {
		m.routeCursor--
	}
	m.screen = screenRoutes
	m.status = fmt.Sprintf("deleted guard %s", deleted)
	m.err = ""
	return m
}

func (m Model) requestQuit() (tea.Model, tea.Cmd) {
	if !m.modified() {
		return m, tea.Quit
	}
	m.previousScreen = m.screen
	m.screen = screenQuitConfirm
	m.status = "production not applied"
	m.err = ""
	return m, nil
}

func (m Model) openWriteFile() (tea.Model, tea.Cmd) {
	m.previousScreen = m.screen
	m.screen = screenWriteFile
	m.writePath = ""
	m.status = fmt.Sprintf("write %s draft", m.target.StatusNoun())
	m.err = ""
	return m, nil
}

func (m Model) openApplyPassphrase() (tea.Model, tea.Cmd) {
	m.previousScreen = m.screen
	m.screen = screenApplyPassphrase
	m.clearApplyPassphrase()
	m.status = "store passphrase required"
	m.err = ""
	return m, nil
}

func (m Model) submitApplyPassphrase() (tea.Model, tea.Cmd) {
	if len(m.applyPassphrase) == 0 {
		m.err = "passphrase is required"
		m.status = "apply needs passphrase"
		return m, nil
	}
	store, ok := m.store.(productionPassphraseStore)
	if !ok {
		m.clearApplyPassphrase()
		m.err = "store does not accept an interactive passphrase"
		m.status = "apply failed"
		return m, nil
	}
	passphrase := passphraseRunesBytes(m.applyPassphrase)
	store.SetPassphrase(passphrase)
	for i := range passphrase {
		passphrase[i] = 0
	}
	m.clearApplyPassphrase()
	m.screen = m.previousScreen
	return m.applyProduction()
}

func (m *Model) clearApplyPassphrase() {
	for i := range m.applyPassphrase {
		m.applyPassphrase[i] = 0
	}
	m.applyPassphrase = nil
}

func passphraseRunesBytes(runes []rune) []byte {
	var out []byte
	for _, r := range runes {
		out = utf8.AppendRune(out, r)
	}
	return out
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

	b.WriteString("\nkeys: up/down move  space/enter cycle  v validate  w write draft  a apply production  q quit\n")
	if m.modified() {
		b.WriteString(modifiedProductionWarning + "\n")
	}
	return m.renderHelp(b.String())
}

func (m Model) routeView() string {
	var b strings.Builder
	routes := m.routes()
	groups := transferGuardGroups(routes)
	b.WriteString(sectionStyle.Render("Transfer Guards"))
	b.WriteString("\n\n")
	b.WriteString(metadataStyle.Render("Blocked Destinations"))
	b.WriteString("\n")
	b.WriteString("  ")
	b.WriteString(ellipsize(blockedDestinationsSummary(m.policy), m.panelWidth()-6))
	b.WriteString("\n\n")
	if m.policy == nil || m.policy.TransferPolicy == nil {
		b.WriteString(readonlyStyle.Render("transfer routing is off; no stored guards are present"))
		b.WriteString("\n")
	} else if len(groups) == 0 {
		b.WriteString(readonlyStyle.Render("no stored guards"))
		b.WriteString("\n")
	} else {
		if m.routeCursor >= len(groups) {
			m.routeCursor = len(groups) - 1
		}
		advanced := false
		for i, group := range groups {
			if group.Advanced {
				advanced = true
			}
			b.WriteString(m.renderGuardGroup(i, group))
			b.WriteString("\n")
		}
		if advanced {
			b.WriteString("\n")
			b.WriteString(descriptionStyle.Render("Advanced rows are YAML-only; press y to inspect or edit the full policy."))
			b.WriteString("\n")
		}
	}
	b.WriteString("\nkeys: up/down move  enter/e edit guard  n new  c clone  d delete  b blocked destinations  u/U reorder  p settings  t asset sets  y yaml  space cycle enabled  v validate  w write draft  a apply production  esc/backspace back  q quit\n")
	if m.modified() {
		b.WriteString(modifiedProductionWarning + "\n")
	}
	return m.renderHelp(b.String())
}

func (m Model) assetSetView() string {
	var b strings.Builder
	rows := m.assetSetRows()
	b.WriteString(sectionStyle.Render("Asset Sets"))
	b.WriteString("\n\n")
	if m.policy == nil || m.policy.TransferPolicy == nil {
		b.WriteString(readonlyStyle.Render("transfer routing is off; no stored asset sets are present"))
		b.WriteString("\n")
	} else if len(rows) == 0 {
		b.WriteString(readonlyStyle.Render("no stored asset sets"))
		b.WriteString("\n")
	} else {
		if m.assetSetCursor >= len(rows) {
			m.assetSetCursor = len(rows) - 1
		}
		for i, row := range rows {
			b.WriteString(m.renderAssetSetRow(i, row))
			b.WriteString("\n")
		}
	}
	b.WriteString("\nkeys: up/down move  enter/e edit set  n new  c clone  d delete  y yaml  v validate  w write draft  a apply production  b back  q quit\n")
	if m.modified() {
		b.WriteString(modifiedProductionWarning + "\n")
	}
	return m.renderHelp(b.String())
}

func (m Model) assetSetEditView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Edit Asset Set"))
	b.WriteString("\n\n")
	nameLine := fmt.Sprintf("%-12s %s", "Name", assetSetEditDisplayValue("name", m.editAssetSetName))
	if m.editCursor == 0 {
		b.WriteString(selectedStyle.Render("  " + nameLine + "  "))
	} else {
		b.WriteString("  " + nameLine)
	}
	b.WriteString("\n\n")
	b.WriteString(metadataStyle.Render("Network mappings"))
	b.WriteString("\n")
	b.WriteString(m.renderAssetSetEditHeader())
	for i, row := range m.editAssetSetRows {
		b.WriteString(m.renderAssetSetEditRow(i, row))
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down/left/right move  enter edit  n add network  x delete network  esc back\n")
	return m.renderHelp(b.String())
}

func (m Model) renderAssetSetEditHeader() string {
	return "  " + metadataStyle.Render(fmt.Sprintf("%-18s %-32s", "Network", "ASA IDs")) + "\n"
}

func (m Model) renderAssetSetEditRow(rowIndex int, row assetSetEditRow) string {
	cells := []struct {
		key   string
		value string
		width int
	}{
		{key: "network", value: row.Network, width: 18},
		{key: "asa_ids", value: assetSetEditDisplayValue("asa_ids", row.ASAIDs), width: 32},
	}
	var parts []string
	for col, cell := range cells {
		selected := m.editCursor == 1+rowIndex*2+col
		line := fixedWidthFieldLine(ellipsize(cell.value, cell.width), cell.width)
		if selected {
			line = selectedStyle.Render(line)
		}
		parts = append(parts, line)
	}
	return "  " + strings.Join(parts, " ")
}

func (m Model) assetSetTextEditView() string {
	title := "Edit " + m.currentAssetSetEditLabel()
	value, ok := m.currentAssetSetEditValue()

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	if !ok {
		b.WriteString(statusErrorStyle.Render("No text field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}
	b.WriteString(descriptionStyle.Render(m.assetSetTextHint(m.currentAssetSetEditKey())))
	b.WriteString("\n\n")
	b.WriteString(inputActiveStyle.Render(fixedWidthFieldLine(m.assetSetTextDisplayValue(value), m.routeTextInputWidth())))
	b.WriteString("\n\n")
	b.WriteString("keys: type edit  backspace delete  ctrl+u clear  enter/esc done\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) routeYAMLView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Transfer Policy YAML"))
	b.WriteString("\n\n")
	lines := strings.Split(strings.TrimRight(m.transferPolicyYAML(), "\n"), "\n")
	visibleLines := m.routeYAMLVisibleLines()
	offset := m.routeYAMLOffset
	if offset < 0 || offset >= len(lines) {
		offset = 0
	}
	end := offset + visibleLines
	if end > len(lines) {
		end = len(lines)
	}

	if offset > 0 {
		b.WriteString(scrollMoreAboveLine(offset))
		b.WriteString("\n")
	}
	for _, line := range lines[offset:end] {
		b.WriteString(ellipsize(line, m.routeYAMLLineWidth()))
		b.WriteString("\n")
	}
	if end < len(lines) {
		b.WriteString(scrollMoreBelowLine(len(lines) - end))
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down/pgup/pgdown scroll  w write draft  a apply production  esc/b back  q quit\n")
	if m.modified() {
		b.WriteString(modifiedProductionWarning + "\n")
	}
	return m.renderHelp(b.String())
}

func (m Model) routeYAMLVisibleLines() int {
	if m.height <= 0 {
		return 20
	}
	visible := m.height - m.appChromeLines() - m.routeYAMLChromeLines()
	if visible < 3 {
		return 3
	}
	return visible
}

func (m Model) appChromeLines() int {
	// panelStyle adds one border line and one padding line at both top and bottom.
	const panelBorderAndPadding = 4
	// Header before screen content: title, subtitle, spacer, store, identity,
	// document, state, and spacer before the active screen.
	lines := 8 + panelBorderAndPadding
	if m.status != "" {
		lines++
	}
	if m.err != "" {
		lines++
	}
	if m.busy {
		lines++
	}
	return lines
}

func (m Model) routeYAMLChromeLines() int {
	// YAML screen title, spacer, both possible scroll markers, spacer, key help.
	lines := 6
	if m.modified() {
		lines++
	}
	return lines
}

func (m Model) routeYAMLLineWidth() int {
	width := m.panelWidth() - 4
	if width < 20 {
		return 20
	}
	return width
}

func (m Model) deleteRouteConfirmView() string {
	routeID := "(missing)"
	if routes := m.routes(); m.deleteRouteIndex >= 0 && m.deleteRouteIndex < len(routes) {
		routeID = routes[m.deleteRouteIndex].ID
	}
	return m.renderHelp(renderLines(
		sectionStyle.Render("Delete Transfer Guard"),
		"",
		statusWarnStyle.Render("Delete guard "+routeID+"?"),
		"",
		"This removes the underlying route from the in-memory policy draft.",
		"Use a from the guard list to apply the draft to production.",
		"",
		"keys: y delete  n cancel  esc cancel",
	))
}

func (m Model) deleteAssetSetConfirmView() string {
	name := m.deleteAssetSetName
	if strings.TrimSpace(name) == "" {
		name = "(missing)"
	}
	return m.renderHelp(renderLines(
		sectionStyle.Render("Delete Asset Set"),
		"",
		statusWarnStyle.Render("Delete asset set "+name+"?"),
		"",
		"This validates the policy draft before removing the set.",
		"Routes that still reference @"+name+" will block deletion.",
		"",
		"keys: y delete  n cancel  esc cancel",
	))
}

func (m Model) quitConfirmView() string {
	return m.renderHelp(renderLines(
		sectionStyle.Render("Production Not Applied"),
		"",
		statusWarnStyle.Render("This policy draft differs from production."),
		"",
		"Press a to apply to production and quit.",
		"Press q to quit without applying to production.",
		"Press esc to return to editing.",
		"",
		"keys: a apply+quit  q quit without applying  esc cancel",
	))
}

func (m Model) applyPassphraseView() string {
	value := strings.Repeat("*", len(m.applyPassphrase))
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Apply To Production"))
	b.WriteString("\n\n")
	b.WriteString(descriptionStyle.Render(fmt.Sprintf("Enter the identity store passphrase to write %s and a fresh sidecar.", m.target.DocumentName())))
	b.WriteString("\n\n")
	b.WriteString(inputActiveStyle.Render(fixedWidthFieldLine(value, m.routeTextInputWidth())))
	b.WriteString("\n\n")
	b.WriteString("keys: type passphrase  backspace delete  ctrl+u clear  enter apply  esc cancel\n")
	return m.renderHelp(m.renderPopup(90, b.String()))
}

func (m Model) writeFileView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Write " + m.target.Label() + " Draft"))
	b.WriteString("\n\n")
	b.WriteString(descriptionStyle.Render(fmt.Sprintf("Write the current in-memory %s draft to a YAML file without applying it to the identity store.", m.target.StatusNoun())))
	b.WriteString("\n\n")
	b.WriteString(inputActiveStyle.Render(fixedWidthFieldLine(m.writePathDisplayValue(), m.routeTextInputWidth())))
	b.WriteString("\n\n")
	b.WriteString("keys: type path  backspace delete  ctrl+u clear  enter write  esc cancel\n")
	return m.renderHelp(m.renderPopup(90, b.String()))
}

func (m Model) transferSettingsView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Transfer Policy Settings"))
	b.WriteString("\n\n")
	b.WriteString(descriptionStyle.Render("Enter opens the selected editor. Enabled is always on or off."))
	b.WriteString("\n\n")
	for i, field := range m.settingsFields {
		line := fmt.Sprintf("%-22s %s", field.label, field.value)
		if i == m.settingsCursor {
			b.WriteString(selectedStyle.Render("  " + line + "  "))
		} else {
			b.WriteString("  " + line)
		}
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down move  enter edit  esc back\n")
	return m.renderHelp(b.String())
}

func (m Model) blockedDestinationsEditView() string {
	field := m.currentBlockedDestinationsListField()
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Edit Blocked Destinations"))
	b.WriteString("\n\n")
	if field == nil {
		b.WriteString(statusErrorStyle.Render("Blocked destinations editor is unavailable."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}
	terms := parseCSV(field.value)
	b.WriteString(metadataStyle.Render(fmt.Sprintf("entries: %d", len(terms))))
	b.WriteString("\n")
	b.WriteString(descriptionStyle.Render(blockedDestinationsListHint()))
	b.WriteString("\n\n")
	b.WriteString(m.routeListInputBox(field.value))
	b.WriteString("\n\n")
	b.WriteString("keys: type edit  comma/space/enter new entry  backspace delete  ctrl+u clear  up/down/pgup/pgdown scroll  esc done\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) transferSettingsChoiceEditView() string {
	key := m.currentSettingsKey()
	title := "Choose Value"
	if key != "" {
		title = "Choose " + m.currentSettingsLabel()
	}
	choices := transferSettingsChoiceOptionsForKey(key)

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	if key == "" || len(choices) == 0 {
		b.WriteString(statusErrorStyle.Render("No choice field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}
	for i, choice := range choices {
		line := "  " + choice
		if i == m.editChoiceCursor {
			b.WriteString(selectedStyle.Render(line + "  "))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down move  enter/space select  esc cancel\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) routeEditView() string {
	var b strings.Builder
	b.WriteString(sectionStyle.Render("Edit Transfer Guard"))
	b.WriteString("\n\n")
	b.WriteString(descriptionStyle.Render("Enter opens the selected editor. Each asset row is stored as one guard_asset route."))
	b.WriteString("\n\n")
	for i, field := range m.editFields {
		line := fmt.Sprintf("%-16s %s", field.label, routeEditFieldDisplayValue(field))
		if i == m.editCursor {
			b.WriteString(selectedStyle.Render("  " + line + "  "))
		} else {
			b.WriteString("  " + line)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(metadataStyle.Render("Assets"))
	b.WriteString("\n")
	b.WriteString(m.renderAssetEditHeader())
	for i, row := range m.editAssetRows {
		b.WriteString(m.renderAssetEditRow(i, row))
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down/left/right move  enter edit  n add asset  x delete asset  esc back\n")
	return m.renderHelp(b.String())
}

func (m Model) renderAssetEditHeader() string {
	widths := m.routeAssetEditColumnWidths()
	labels := []string{"Asset", "Review Above", "Reject Above"}
	parts := make([]string, 0, len(labels))
	for i, label := range labels {
		parts = append(parts, fixedWidthFieldLine(ellipsize(label, widths[i]), widths[i]))
	}
	return "  " + metadataStyle.Render(strings.Join(parts, " ")) + "\n"
}

func (m Model) renderAssetEditRow(rowIndex int, row routeEditAssetRow) string {
	cells := []string{
		routeAssetCellDisplay(row.asset),
		routeAssetCellDisplay(row.reviewAbove),
		routeAssetCellDisplay(row.rejectAbove),
	}
	widths := m.routeAssetEditColumnWidths()
	var parts []string
	for col := 0; col < len(cells); col++ {
		selected := m.editCursor == len(m.editFields)+rowIndex*routeEditAssetColumnCount+col
		cell := fixedWidthFieldLine(ellipsize(cells[col], widths[col]), widths[col])
		if selected {
			cell = selectedStyle.Render(cell)
		}
		parts = append(parts, cell)
	}
	return "  " + strings.Join(parts, " ")
}

func (m Model) routeAssetEditColumnWidths() []int {
	available := m.panelWidth() - 8
	if available < 34 {
		available = 34
	}
	widths := []int{10, 10, 10}
	extra := available - 2 - 30
	grow := []int{24, 6, 6}
	for i := range widths {
		if extra <= 0 {
			break
		}
		add := grow[i]
		if add > extra {
			add = extra
		}
		widths[i] += add
		extra -= add
	}
	return widths
}

func routeAssetCellDisplay(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func (m Model) routeListEditView() string {
	field := m.currentRouteListField()
	title := "Edit List"
	if field != nil {
		title = "Edit " + field.label
	}

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	if field == nil {
		b.WriteString(statusErrorStyle.Render("No list field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}

	terms := parseCSV(field.value)
	b.WriteString(metadataStyle.Render(fmt.Sprintf("entries: %d", len(terms))))
	b.WriteString("\n")
	b.WriteString(descriptionStyle.Render(routeListHint(field.key)))
	b.WriteString("\n\n")
	b.WriteString(m.routeListInputBox(field.value))
	b.WriteString("\n\n")
	b.WriteString("keys: type edit  comma/space/enter new entry  backspace delete  ctrl+u clear  up/down/pgup/pgdown scroll  esc done\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) routeListInputBox(value string) string {
	lines := routeListLines(value)
	if len(lines) == 0 {
		lines = []string{""}
	}
	if m.screen == screenRouteListEdit || m.screen == screenBlockedDestinationsEdit {
		lines = append([]string(nil), lines...)
		lines[len(lines)-1] += "_"
	}

	visibleLines := m.routeListVisibleLines()
	offset := m.editListOffset
	maxOffset := maxOffsetForLines(lines, visibleLines)
	if offset < 0 {
		offset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}
	end := offset + visibleLines
	if end > len(lines) {
		end = len(lines)
	}

	var b strings.Builder
	if offset > 0 {
		b.WriteString(scrollMoreAboveLine(offset))
		b.WriteString("\n")
	}
	displayLines := append([]string(nil), lines[offset:end]...)
	for len(displayLines) < visibleLines {
		displayLines = append(displayLines, "")
	}
	width := m.routeListInputWidth()
	for i, line := range displayLines {
		displayLines[i] = fixedWidthFieldLine(line, width)
	}
	b.WriteString(inputActiveStyle.Render(strings.Join(displayLines, "\n")))
	if end < len(lines) {
		b.WriteString("\n")
		b.WriteString(scrollMoreBelowLine(len(lines) - end))
	}
	return b.String()
}

func (m Model) routeTextEditView() string {
	key := m.currentEditKey()
	title := "Edit Text"
	if key != "" {
		title = "Edit " + m.currentEditLabel()
	}

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	value, ok := m.currentEditValue()
	if key == "" || !ok {
		b.WriteString(statusErrorStyle.Render("No text field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}
	b.WriteString(descriptionStyle.Render(m.routeTextHint(key)))
	b.WriteString("\n\n")
	b.WriteString(inputActiveStyle.Render(fixedWidthFieldLine(m.routeTextDisplayValue(value), m.routeTextInputWidth())))
	b.WriteString("\n\n")
	b.WriteString("keys: type edit  backspace delete  ctrl+u clear  enter/esc done\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) routeChoiceEditView() string {
	key := m.currentEditKey()
	title := "Choose Value"
	if key != "" {
		title = "Choose " + m.currentEditLabel()
	}
	choices := routeChoiceOptionsForKey(key)

	var b strings.Builder
	b.WriteString(sectionStyle.Render(title))
	b.WriteString("\n\n")
	if key == "" || len(choices) == 0 {
		b.WriteString(statusErrorStyle.Render("No choice field is selected."))
		b.WriteString("\n\nkeys: esc back\n")
		return m.renderHelp(m.renderPopup(80, b.String()))
	}
	for i, choice := range choices {
		line := "  " + choice
		if i == m.editChoiceCursor {
			b.WriteString(selectedStyle.Render(line + "  "))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	b.WriteString("\nkeys: up/down move  enter/space select  esc cancel\n")
	return m.renderHelp(m.renderPopup(80, b.String()))
}

func (m Model) panelWidth() int {
	if m.width > 0 {
		w := m.width - 6
		if w < 60 {
			return 60
		}
		return w
	}
	return 96
}

func (m Model) renderPopup(maxWidth int, body string) string {
	return popupStyle.Width(m.popupWidth(maxWidth)).Render(constrainPopupBody(body, m.popupContentHeight()))
}

func (m Model) popupWidth(max int) int {
	if m.width <= 0 {
		return max
	}
	w := m.panelWidth() - 6
	if w < 40 {
		return 40
	}
	if max > 0 && w > max {
		return max
	}
	return w
}

func (m Model) popupBodyWidth(max int) int {
	w := m.popupWidth(max) - popupStyle.GetHorizontalFrameSize()
	if w < 1 {
		return 1
	}
	return w
}

func (m Model) popupContentHeight() int {
	if m.height <= 0 {
		return 0
	}
	h := m.height - m.appChromeLines() - popupStyle.GetVerticalFrameSize()
	if h < 1 {
		return 1
	}
	return h
}

func (m Model) renderFieldRow(i int, field field) string {
	rawValue := field.value(m.policy)
	rawSource := ""
	if field.source != nil {
		rawSource = field.source(m.policy)
	}
	labelCell := fixedWidthFieldLine(field.label, policyFieldLabelWidth)
	valueCell := fixedWidthFieldLine(rawValue, policyFieldValueWidth)
	styledValue := valueStyle.Render(valueCell)
	styledSource := metadataStyle.Render(rawSource)
	if field.kind == fieldReadonly {
		styledValue = readonlyStyle.Render(valueCell)
	}
	line := labelCell + " " + styledValue + " " + styledSource
	if i == m.cursor {
		return selectedStyle.Render("  " + labelCell + " " + valueCell + " " + rawSource + "  ")
	}
	return "  " + line
}

func (m Model) renderGuardGroup(i int, group transferGuardGroup) string {
	name := group.ID
	if description := strings.TrimSpace(group.Description); description != "" {
		name += " - " + description
	}
	var line string
	if group.Advanced {
		line = fmt.Sprintf("%s  advanced: %s", name, group.AdvancedReason)
	} else {
		line = fmt.Sprintf("%s  net=%s src=%s dst=%s %s=%s",
			name,
			guardTermSummary(group.Networks),
			guardTermSummary(group.Sources),
			guardTermSummary(group.Destinations),
			guardGroupAssetLabel(group),
			guardGroupAssetSummary(group),
		)
	}
	line = ellipsize(line, m.panelWidth()-6)
	if i == m.routeCursor {
		return selectedStyle.Render("  " + line + "  ")
	}
	return "  " + line
}

func (m Model) renderAssetSetRow(i int, row assetSetRow) string {
	line := fmt.Sprintf("%s  networks=%d assets=%d  %s", row.Name, row.NetworkCount, row.ASAIDCount, row.Preview)
	line = ellipsize(line, m.panelWidth()-6)
	if i == m.assetSetCursor {
		return selectedStyle.Render("  " + line + "  ")
	}
	return "  " + line
}

func guardGroupAssetLabel(group transferGuardGroup) string {
	if len(group.AssetRows) == 1 {
		return "asset"
	}
	return "assets"
}

func guardGroupAssetSummary(group transferGuardGroup) string {
	if group.Advanced {
		return "-"
	}
	switch len(group.AssetRows) {
	case 0:
		return "-"
	case 1:
		return emptyGuardDisplay(group.AssetRows[0].Asset)
	default:
		return fmt.Sprintf("%d", len(group.AssetRows))
	}
}

func guardTermSummary(terms []string) string {
	switch len(terms) {
	case 0:
		return "-"
	case 1:
		return terms[0]
	default:
		return fmt.Sprintf("%d", len(terms))
	}
}

func blockedDestinationsSummary(c *policy.StoredConfig) string {
	if c == nil || c.TransferPolicy == nil || len(c.TransferPolicy.BlockedDestinations) == 0 {
		return "-"
	}
	if len(c.TransferPolicy.BlockedDestinations) == 1 {
		return c.TransferPolicy.BlockedDestinations[0]
	}
	return fmt.Sprintf("%d destinations", len(c.TransferPolicy.BlockedDestinations))
}

func emptyGuardDisplay(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func (m Model) renderHelp(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "keys:") || strings.HasPrefix(line, modifiedProductionWarning) {
			lines[i] = helpStyle.Render(line)
		}
	}
	return strings.Join(lines, "\n")
}

func scrollMoreAboveLine(count int) string {
	return scrollMoreLine(count, "above")
}

func scrollMoreBelowLine(count int) string {
	return scrollMoreLine(count, "below")
}

func scrollMoreLine(count int, direction string) string {
	if count <= 0 {
		return ""
	}
	return descriptionStyle.Render(fmt.Sprintf("  %d more %s", count, direction))
}

func fixedWidthFieldLine(line string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(line)
	if len(runes) > width {
		return string(runes[:width])
	}
	if len(runes) < width {
		return line + strings.Repeat(" ", width-len(runes))
	}
	return line
}

func constrainPopupBody(body string, maxLines int) string {
	if maxLines <= 0 {
		return body
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:maxLines], "\n")
}

func ellipsize(s string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}

func statusStyle(m Model) lipgloss.Style {
	if m.err != "" {
		return statusErrorStyle
	}
	if m.modified() || m.busy {
		return statusWarnStyle
	}
	return statusOKStyle
}

func stateStyle(state string) lipgloss.Style {
	if state == "modified" {
		return statusWarnStyle
	}
	return statusOKStyle
}

func (m Model) applyProduction() (tea.Model, tea.Cmd) {
	cp, baseline, err := m.cloneStored(m.policy)
	if err != nil {
		m.err = err.Error()
		m.status = "cannot apply"
		return m, nil
	}
	if store, ok := m.store.(productionPassphraseStore); ok && store.RequiresPassphraseForSave() {
		return m.openApplyPassphrase()
	}
	m.busy = true
	m.status = fmt.Sprintf("applying %s", m.target.StatusNoun())
	m.err = ""
	return m, func() tea.Msg {
		if err := m.store.Save(context.Background(), cp); err != nil {
			return productionApplyResultMsg{err: err}
		}
		return productionApplyResultMsg{baseline: baseline}
	}
}

func (m Model) writeDraftFile() (tea.Model, tea.Cmd) {
	path := strings.TrimSpace(m.writePath)
	if path == "" {
		m.err = "path is required"
		m.status = "write failed"
		return m, nil
	}
	data, err := m.marshalStored(m.policy)
	if err != nil {
		m.err = err.Error()
		m.status = "write failed"
		return m, nil
	}
	m.busy = true
	m.status = fmt.Sprintf("writing %s draft", m.target.StatusNoun())
	m.err = ""
	return m, func() tea.Msg {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return writeFileResultMsg{path: path, err: err}
		}
		return writeFileResultMsg{path: path}
	}
}

func (m Model) validate() (tea.Model, tea.Cmd) {
	cp, _, err := m.cloneStored(m.policy)
	if err != nil {
		m.err = err.Error()
		m.status = "cannot validate"
		return m, nil
	}
	m.busy = true
	m.status = fmt.Sprintf("validating %s", m.target.StatusNoun())
	m.err = ""
	return m, func() tea.Msg {
		return validateResultMsg{err: m.store.Validate(context.Background(), cp)}
	}
}

func friendlyPolicyError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "asset_sources requires clawback.allow:true"):
		return msg + " (clear Asset Sources for normal sends, or set Clawback Allow to true for clawback routes)"
	case strings.Contains(msg, "clawback.allow:true requires asset_sources"):
		return msg + " (set Asset Sources for clawback routes, or set Clawback Allow to false for normal routes)"
	case strings.Contains(msg, "self is not allowed in clawback route destinations"):
		return msg + " (clawback destinations must be explicit addresses or address sets, not self)"
	case strings.Contains(msg, "self is not allowed in asset_sources"):
		return msg + " (asset_sources names the clawback source account; use an address, set, or wildcard)"
	case strings.Contains(msg, "close.allow:true with wildcard destinations is not supported"):
		return msg + " (for close-out routes, replace wildcard Destinations with explicit addresses or address sets)"
	case strings.Contains(msg, "duplicate route id"):
		return msg + " (route IDs must be unique)"
	case strings.Contains(msg, "unresolved asset set"):
		return msg + " (define the asset set from Transfer Guards -> Asset Sets, then reference it as @name)"
	default:
		return msg
	}
}

func (m Model) modified() bool {
	current, err := m.marshalStored(m.policy)
	if err != nil {
		return true
	}
	return string(current) != string(m.baseline)
}

func policyFieldsForTarget(target policyeditor.Target) []field {
	if target == policyeditor.TargetSentry {
		return sentryPolicyFields()
	}
	return signerPolicyFields()
}

func signerPolicyFields() []field {
	return []field{
		boolField("reject_foreign_rekey", "Reject foreign rekey", true, func(c *policy.StoredConfig) **bool {
			return &c.RejectForeignRekey
		}),
		boolField("reject_close_remainder", "Reject close remainder", false, func(c *policy.StoredConfig) **bool {
			return &c.RejectCloseRemainder
		}),
		boolField("reject_asset_close", "Reject asset close", false, func(c *policy.StoredConfig) **bool {
			return &c.RejectAssetClose
		}),
		boolField("reject_clawback", "Reject clawback", false, func(c *policy.StoredConfig) **bool {
			return &c.RejectClawback
		}),
		boolField("always_review_warnings", "Always review warnings", false, func(c *policy.StoredConfig) **bool {
			return &c.AlwaysReviewWarnings
		}),
		boolField("auto_approve_self_noop_transfer", "Auto-approve self no-op transfer", false, func(c *policy.StoredConfig) **bool {
			return &c.AutoApproveSelfNoOpTransfer
		}),
		{
			key:   "max_fee_microalgos",
			label: "Max fee microAlgos",
			kind:  fieldReadonly,
			value: func(c *policy.StoredConfig) string {
				if c == nil || c.MaxFeeMicroAlgos == nil {
					return "0 (no limit)"
				}
				return fmt.Sprintf("%d", *c.MaxFeeMicroAlgos)
			},
			source: func(c *policy.StoredConfig) string {
				if c == nil || c.MaxFeeMicroAlgos == nil {
					return "default"
				}
				return "explicit"
			},
		},
		{
			key:   "transfer_policy",
			label: "Transfer routing",
			kind:  fieldReadonly,
			value: transferPolicySummary,
			source: func(c *policy.StoredConfig) string {
				if c == nil || c.TransferPolicy == nil {
					return "absent"
				}
				return "explicit"
			},
		},
	}
}

func sentryPolicyFields() []field {
	return []field{
		boolField("reject_rekey", "Reject rekey", true, func(c *policy.StoredConfig) **bool {
			return &c.RejectRekey
		}),
		boolField("reject_close_remainder", "Reject close remainder", false, func(c *policy.StoredConfig) **bool {
			return &c.RejectCloseRemainder
		}),
		boolField("reject_asset_close", "Reject asset close", false, func(c *policy.StoredConfig) **bool {
			return &c.RejectAssetClose
		}),
		boolField("reject_clawback", "Reject clawback", false, func(c *policy.StoredConfig) **bool {
			return &c.RejectClawback
		}),
		{
			key:   "max_fee_microalgos",
			label: "Max fee microAlgos",
			kind:  fieldReadonly,
			value: func(c *policy.StoredConfig) string {
				if c == nil || c.MaxFeeMicroAlgos == nil {
					return "0 (no limit)"
				}
				return fmt.Sprintf("%d", *c.MaxFeeMicroAlgos)
			},
			source: func(c *policy.StoredConfig) string {
				if c == nil || c.MaxFeeMicroAlgos == nil {
					return "default"
				}
				return "explicit"
			},
		},
		{
			key:   "transfer_policy",
			label: "Transfer routing",
			kind:  fieldReadonly,
			value: transferPolicySummary,
			source: func(c *policy.StoredConfig) string {
				if c == nil || c.TransferPolicy == nil {
					return "absent"
				}
				return "explicit"
			},
		},
	}
}

func boolField(key, label string, defaultValue bool, ptr func(*policy.StoredConfig) **bool) field {
	return field{
		key:   key,
		label: label,
		kind:  fieldBool,
		value: func(c *policy.StoredConfig) string {
			if c == nil || *ptr(c) == nil {
				return fmt.Sprintf("%t", defaultValue)
			}
			if **ptr(c) {
				return "true"
			}
			return "false"
		},
		source: func(c *policy.StoredConfig) string {
			if c == nil || *ptr(c) == nil {
				return "default"
			}
			return "explicit"
		},
		cycle: func(c *policy.StoredConfig) {
			if c == nil {
				return
			}
			slot := ptr(c)
			*slot = nextBoolOverride(*slot, defaultValue)
		},
	}
}

func transferPolicySummary(c *policy.StoredConfig) string {
	if c == nil || c.TransferPolicy == nil {
		return "enabled=false routes=0"
	}
	enabled := "false"
	if c.TransferPolicy.Enabled != nil {
		enabled = fmt.Sprintf("%t", *c.TransferPolicy.Enabled)
	}
	return fmt.Sprintf("enabled=%s routes=%d", enabled, len(c.TransferPolicy.Routes))
}

func (m Model) transferPolicyYAML() string {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return "transfer_policy: null\n"
	}
	data, err := m.target.Marshal(&policy.StoredConfig{
		TransferPolicy: cloneTransferPolicy(m.policy.TransferPolicy),
	})
	if err != nil {
		return fmt.Sprintf("# failed to render transfer_policy: %v\n", err)
	}
	return string(data)
}

func (m Model) routeYAMLMaxOffset() int {
	lines := strings.Split(strings.TrimRight(m.transferPolicyYAML(), "\n"), "\n")
	maxOffset := len(lines) - m.routeYAMLVisibleLines()
	if maxOffset < 0 {
		return 0
	}
	return maxOffset
}

func (m *Model) ensureTransferPolicy() {
	if m.policy == nil {
		m.policy = &policy.StoredConfig{}
	}
	if m.policy.TransferPolicy != nil {
		return
	}
	enabled := false
	onNoRoute := string(policy.TransferOnNoRouteReject)
	closeOnNoRoute := string(policy.TransferOnNoRouteReject)
	clawbackOnNoRoute := string(policy.TransferOnNoRouteReject)
	m.policy.TransferPolicy = &policy.StoredTransferPolicy{
		SchemaVersion:     1,
		Enabled:           &enabled,
		OnNoRoute:         &onNoRoute,
		CloseOnNoRoute:    &closeOnNoRoute,
		ClawbackOnNoRoute: &clawbackOnNoRoute,
		AssetSets:         defaultAssetSets(),
		RoutesSet:         true,
	}
}

func (m *Model) enableTransferPolicyForGuards() {
	m.ensureTransferPolicy()
	enabled := true
	m.policy.TransferPolicy.Enabled = &enabled
	if m.policy.TransferPolicy.OnNoRoute == nil {
		onNoRoute := string(policy.TransferOnNoRouteReject)
		m.policy.TransferPolicy.OnNoRoute = &onNoRoute
	}
	if m.policy.TransferPolicy.CloseOnNoRoute == nil {
		closeOnNoRoute := string(policy.TransferOnNoRouteReject)
		m.policy.TransferPolicy.CloseOnNoRoute = &closeOnNoRoute
	}
	if m.policy.TransferPolicy.ClawbackOnNoRoute == nil {
		clawbackOnNoRoute := string(policy.TransferOnNoRouteReject)
		m.policy.TransferPolicy.ClawbackOnNoRoute = &clawbackOnNoRoute
	}
}

func (m *Model) cancelFormApply() {
	m.formApplyToken++
	m.busy = false
}

func (m Model) newRoute() policy.StoredTransferRoute {
	asset := "algo"
	name := m.uniqueGuardName("new_guard", []string{asset})
	return policy.StoredTransferRoute{
		ID:           guardRouteID(name, asset),
		Networks:     []string{"*"},
		Sources:      []string{"*"},
		Assets:       []policy.StoredAssetTerm{{Raw: asset}},
		Destinations: []string{"self"},
	}
}

func (m Model) openGuardGroupEditor(group transferGuardGroup) Model {
	if group.Advanced {
		m.status = "advanced route is YAML-only; press y to inspect or edit"
		m.err = group.AdvancedReason
		return m
	}
	for _, row := range group.AssetRows {
		if row.ReviewAbove != nil || row.RejectAbove != nil {
			if _, _, err := m.guardAmountMetadata(row.Asset, group.Networks, true); err != nil {
				m.status = "guard amount metadata unavailable; press y to inspect or edit"
				m.err = err.Error()
				return m
			}
		}
	}
	m.screen = screenRouteEdit
	m.editGroupIndex = group.Index
	m.editRouteIndex = -1
	if len(group.RouteIndexes) > 0 {
		m.editRouteIndex = group.RouteIndexes[0]
	}
	m.editCursor = 0
	m.editFields = m.guardGroupToEditFields(group)
	m.editAssetRows = m.guardGroupToEditAssetRows(group)
	m.status = fmt.Sprintf("editing guard %s", group.ID)
	m.err = ""
	return m
}

func (m Model) openTransferSettings() Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.ensureTransferPolicy()
	}
	m.screen = screenTransferSettings
	m.settingsCursor = 0
	m.settingsFields = transferSettingsToFields(m.policy.TransferPolicy)
	m.status = "editing transfer policy settings"
	m.err = ""
	return m
}

func (m Model) openAssetSets() Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.ensureTransferPolicy()
	}
	status := "asset sets"
	if m.seedDefaultAssetSets() {
		status = "added default usdc asset set"
	}
	m.screen = screenAssetSets
	m.assetSetCursor = 0
	m.status = status
	m.err = ""
	return m
}

func (m *Model) seedDefaultAssetSets() bool {
	if m.policy == nil || m.policy.TransferPolicy == nil || len(m.policy.TransferPolicy.AssetSets) > 0 {
		return false
	}
	defaults := defaultAssetSets()
	if len(defaults) == 0 {
		return false
	}
	m.policy.TransferPolicy.AssetSets = defaults
	return true
}

func (m Model) openAssetSetEditor(row assetSetRow) Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.status = "transfer policy is not initialized"
		return m
	}
	set := m.policy.TransferPolicy.AssetSets[row.Name]
	m.screen = screenAssetSetEdit
	m.editAssetSetIndex = row.Index
	m.editAssetSetOriginalName = row.Name
	m.editAssetSetName = row.Name
	m.editAssetSetRows = assetSetToEditRows(set)
	m.editCursor = 0
	m.editListOffset = 0
	m.status = fmt.Sprintf("editing asset set %s", row.Name)
	m.err = ""
	return m
}

func (m Model) openNewAssetSetEditor() Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.ensureTransferPolicy()
	}
	m.screen = screenAssetSetEdit
	m.editAssetSetIndex = -1
	m.editAssetSetOriginalName = ""
	name, rows := m.defaultNewAssetSet()
	m.editAssetSetName = name
	m.editAssetSetRows = rows
	m.editCursor = 0
	m.editListOffset = 0
	m.status = "editing new asset set"
	m.err = ""
	return m
}

func (m Model) defaultNewAssetSet() (string, []assetSetEditRow) {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return "usdc", assetSetToEditRows(defaultUSDCAssetSet())
	}
	if _, ok := m.policy.TransferPolicy.AssetSets["usdc"]; !ok {
		rows := assetSetToEditRows(defaultUSDCAssetSet())
		if len(rows) > 0 {
			return "usdc", rows
		}
	}
	return m.uniqueAssetSetName("asset_set"), []assetSetEditRow{{Network: "testnet"}}
}

func (m Model) openClonedAssetSetEditor(row assetSetRow) Model {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		m.status = "transfer policy is not initialized"
		return m
	}
	set := m.policy.TransferPolicy.AssetSets[row.Name]
	m.screen = screenAssetSetEdit
	m.editAssetSetIndex = -1
	m.editAssetSetOriginalName = ""
	m.editAssetSetName = m.uniqueAssetSetName(row.Name + "_copy")
	m.editAssetSetRows = assetSetToEditRows(set)
	m.editCursor = 0
	m.editListOffset = 0
	m.status = fmt.Sprintf("editing clone of asset set %s", row.Name)
	m.err = ""
	return m
}

func (m Model) openBlockedDestinationsEditor() Model {
	destinations := []string(nil)
	if m.policy != nil && m.policy.TransferPolicy != nil {
		destinations = m.policy.TransferPolicy.BlockedDestinations
	}
	value := routeListStorageValue(destinations)
	if value != "" {
		value += "\n"
	}
	m.blockedDestinationsFields = []routeEditField{{
		key:   "blocked_destinations",
		label: "Blocked Destinations",
		value: value,
	}}
	m.screen = screenBlockedDestinationsEdit
	m.editListOffset = 0
	m.status = "editing blocked destinations"
	m.err = ""
	return m
}

func transferSettingsToFields(tp *policy.StoredTransferPolicy) []routeEditField {
	if tp == nil {
		return nil
	}
	enabled := "false"
	if tp.Enabled != nil {
		enabled = fmt.Sprintf("%t", *tp.Enabled)
	}
	onNoRoute := "default"
	if tp.OnNoRoute != nil {
		onNoRoute = *tp.OnNoRoute
	}
	closeOnNoRoute := string(policy.TransferOnNoRouteReject)
	if tp.CloseOnNoRoute != nil {
		closeOnNoRoute = *tp.CloseOnNoRoute
	}
	clawbackOnNoRoute := string(policy.TransferOnNoRouteReject)
	if tp.ClawbackOnNoRoute != nil {
		clawbackOnNoRoute = *tp.ClawbackOnNoRoute
	}
	return []routeEditField{
		{key: "enabled", label: "Enabled", value: enabled},
		{key: "on_no_route", label: "On No Route", value: onNoRoute},
		{key: "close_on_no_route", label: "Close On No Route", value: closeOnNoRoute},
		{key: "clawback_on_no_route", label: "Clawback On No Route", value: clawbackOnNoRoute},
	}
}

func (m Model) currentSettingsField() *routeEditField {
	if m.settingsCursor < 0 || m.settingsCursor >= len(m.settingsFields) {
		return nil
	}
	return &m.settingsFields[m.settingsCursor]
}

func (m Model) currentSettingsKey() string {
	if field := m.currentSettingsField(); field != nil {
		return field.key
	}
	return ""
}

func (m Model) currentSettingsLabel() string {
	if field := m.currentSettingsField(); field != nil {
		return field.label
	}
	return "Field"
}

func (m Model) currentSettingsValue() (string, bool) {
	if field := m.currentSettingsField(); field != nil {
		return field.value, true
	}
	return "", false
}

func (m *Model) setCurrentSettingsValue(value string) {
	if m.settingsCursor < 0 || m.settingsCursor >= len(m.settingsFields) {
		return
	}
	m.settingsFields[m.settingsCursor].value = value
}

func (m Model) openTransferSettingsFieldEditor() Model {
	key := m.currentSettingsKey()
	if key == "" {
		m.status = "select a field to edit"
		return m
	}
	switch transferSettingsEditorKind(key) {
	case "choice":
		return m.openTransferSettingsChoiceEditor()
	default:
		m.status = "selected field is read-only"
		return m
	}
}

func (m Model) openTransferSettingsChoiceEditor() Model {
	key := m.currentSettingsKey()
	choices := transferSettingsChoiceOptionsForKey(key)
	if key == "" || len(choices) == 0 {
		m.status = "select a choice field to edit"
		return m
	}
	m.screen = screenTransferSettingsChoiceEdit
	m.editChoiceCursor = 0
	current, _ := m.currentSettingsValue()
	current = strings.TrimSpace(current)
	for i, choice := range choices {
		if choice == current {
			m.editChoiceCursor = i
			break
		}
	}
	m.status = "choosing " + strings.ToLower(m.currentSettingsLabel())
	m.err = ""
	return m
}

func transferSettingsEditorKind(key string) string {
	switch key {
	case "enabled", "on_no_route", "close_on_no_route", "clawback_on_no_route":
		return "choice"
	default:
		return "text"
	}
}

func transferSettingsChoiceOptionsForKey(key string) []string {
	switch key {
	case "enabled":
		return []string{"true", "false"}
	case "on_no_route", "close_on_no_route", "clawback_on_no_route":
		return []string{"default", "reject", "review", "operator_default"}
	default:
		return nil
	}
}

func blockedDestinationsListHint() string {
	return "One destination address per line. These destinations are blocked before transfer routes."
}

func (m Model) applyBlockedDestinationsEdit() (tea.Model, tea.Cmd) {
	destinations := []string(nil)
	if field := m.currentBlockedDestinationsListField(); field != nil {
		destinations = parseCSV(field.value)
	}
	draft, err := m.policyWithBlockedDestinations(destinations)
	if err != nil {
		m.err = err.Error()
		m.status = "blocked destinations save failed"
		return m, nil
	}
	m.busy = true
	m.formApplyToken++
	token := m.formApplyToken
	m.err = ""
	m.status = "validating blocked destinations"
	return m, func() tea.Msg {
		return blockedDestinationsApplyResultMsg{
			token:        token,
			destinations: destinations,
			err:          m.store.Validate(context.Background(), draft),
		}
	}
}

func (m Model) applyTransferSettings() (tea.Model, tea.Cmd) {
	tp, err := editFieldsToTransferSettings(m.settingsFields, m.policy.TransferPolicy)
	if err != nil {
		m.err = err.Error()
		m.status = "transfer settings parse failed"
		return m, nil
	}
	draft, err := m.policyWithTransferSettings(tp)
	if err != nil {
		m.err = err.Error()
		m.status = "transfer settings save failed"
		return m, nil
	}
	m.busy = true
	m.formApplyToken++
	token := m.formApplyToken
	m.err = ""
	m.status = "validating transfer policy settings"
	return m, func() tea.Msg {
		return transferSettingsApplyResultMsg{token: token, policy: tp, err: m.store.Validate(context.Background(), draft)}
	}
}

func editFieldsToTransferSettings(fields []routeEditField, current *policy.StoredTransferPolicy) (*policy.StoredTransferPolicy, error) {
	if current == nil {
		current = &policy.StoredTransferPolicy{SchemaVersion: 1}
	}
	tp := cloneTransferPolicy(current)
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		values[field.key] = strings.TrimSpace(field.value)
	}
	enabled, err := parseRequiredBool(values["enabled"])
	if err != nil {
		return nil, fmt.Errorf("enabled: %w", err)
	}
	onNoRoute, err := parseOnNoRoute("on_no_route", values["on_no_route"])
	if err != nil {
		return nil, err
	}
	closeOnNoRoute, err := parseOnNoRoute("close_on_no_route", values["close_on_no_route"])
	if err != nil {
		return nil, err
	}
	clawbackOnNoRoute, err := parseOnNoRoute("clawback_on_no_route", values["clawback_on_no_route"])
	if err != nil {
		return nil, err
	}
	tp.SchemaVersion = 1
	tp.Enabled = enabled
	tp.OnNoRoute = onNoRoute
	tp.CloseOnNoRoute = closeOnNoRoute
	tp.ClawbackOnNoRoute = clawbackOnNoRoute
	return tp, nil
}

func parseOnNoRoute(field, raw string) (*string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", "default", "inherit", "-":
		return nil, nil
	case string(policy.TransferOnNoRouteReject), string(policy.TransferOnNoRouteReview), string(policy.TransferOnNoRouteOperatorDefault):
		return &raw, nil
	default:
		return nil, fmt.Errorf("%s: expected reject, review, operator_default, or default", field)
	}
}

func cloneTransferPolicy(tp *policy.StoredTransferPolicy) *policy.StoredTransferPolicy {
	if tp == nil {
		return nil
	}
	out := *tp
	if tp.Enabled != nil {
		v := *tp.Enabled
		out.Enabled = &v
	}
	if tp.OnNoRoute != nil {
		v := *tp.OnNoRoute
		out.OnNoRoute = &v
	}
	if tp.CloseOnNoRoute != nil {
		v := *tp.CloseOnNoRoute
		out.CloseOnNoRoute = &v
	}
	if tp.ClawbackOnNoRoute != nil {
		v := *tp.ClawbackOnNoRoute
		out.ClawbackOnNoRoute = &v
	}
	out.BlockedDestinations = append([]string(nil), tp.BlockedDestinations...)
	if tp.AddressSets != nil {
		out.AddressSets = make(map[string]policy.StoredAddressSet, len(tp.AddressSets))
		for name, set := range tp.AddressSets {
			out.AddressSets[name] = cloneAddressSet(set)
		}
	}
	if tp.AssetSets != nil {
		out.AssetSets = make(map[string]policy.StoredAssetSet, len(tp.AssetSets))
		for name, set := range tp.AssetSets {
			cp := make(policy.StoredAssetSet, len(set))
			for network, assets := range set {
				cp[network] = append([]uint64(nil), assets...)
			}
			out.AssetSets[name] = cp
		}
	}
	out.Routes = make([]policy.StoredTransferRoute, 0, len(tp.Routes))
	for _, route := range tp.Routes {
		out.Routes = append(out.Routes, cloneRoute(route))
	}
	return &out
}

func cloneAddressSet(set policy.StoredAddressSet) policy.StoredAddressSet {
	return policy.StoredAddressSet{
		Flat:      append([]string(nil), set.Flat...),
		ByNetwork: cloneStringSliceMap(set.ByNetwork),
	}
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func (m Model) policyWithTransferSettings(tp *policy.StoredTransferPolicy) (*policy.StoredConfig, error) {
	draft, _, err := m.cloneStored(m.policy)
	if err != nil {
		return nil, err
	}
	draft.TransferPolicy = tp
	return draft, nil
}

func (m Model) policyWithBlockedDestinations(destinations []string) (*policy.StoredConfig, error) {
	draft, _, err := m.cloneStored(m.policy)
	if err != nil {
		return nil, err
	}
	if draft.TransferPolicy == nil {
		draft.TransferPolicy = m.defaultBlockedDestinationsTransferPolicy()
	}
	draft.TransferPolicy.BlockedDestinations = append([]string(nil), destinations...)
	return draft, nil
}

func (m Model) defaultBlockedDestinationsTransferPolicy() *policy.StoredTransferPolicy {
	enabled := true
	onNoRoute := string(policy.TransferOnNoRouteReject)
	if m.target == policyeditor.TargetSigner {
		onNoRoute = string(policy.TransferOnNoRouteOperatorDefault)
	}
	closeOnNoRoute := string(policy.TransferOnNoRouteReject)
	clawbackOnNoRoute := string(policy.TransferOnNoRouteReject)
	return &policy.StoredTransferPolicy{
		SchemaVersion:     1,
		Enabled:           &enabled,
		OnNoRoute:         &onNoRoute,
		CloseOnNoRoute:    &closeOnNoRoute,
		ClawbackOnNoRoute: &clawbackOnNoRoute,
		RoutesSet:         true,
	}
}

func (m Model) policyWithEditedAssetSet(oldName, name string, set policy.StoredAssetSet) (*policy.StoredConfig, error) {
	draft, _, err := m.cloneStored(m.policy)
	if err != nil {
		return nil, err
	}
	if draft.TransferPolicy == nil {
		enabled := true
		onNoRoute := string(policy.TransferOnNoRouteReject)
		closeOnNoRoute := string(policy.TransferOnNoRouteReject)
		clawbackOnNoRoute := string(policy.TransferOnNoRouteReject)
		draft.TransferPolicy = &policy.StoredTransferPolicy{
			SchemaVersion:     1,
			Enabled:           &enabled,
			OnNoRoute:         &onNoRoute,
			CloseOnNoRoute:    &closeOnNoRoute,
			ClawbackOnNoRoute: &clawbackOnNoRoute,
			RoutesSet:         true,
		}
	}
	if draft.TransferPolicy.AssetSets == nil {
		draft.TransferPolicy.AssetSets = make(map[string]policy.StoredAssetSet)
	}
	if oldName != "" && oldName != name {
		delete(draft.TransferPolicy.AssetSets, oldName)
	}
	draft.TransferPolicy.AssetSets[name] = cloneAssetSet(set)
	return draft, nil
}

func (m Model) policyWithDeletedAssetSet(name string) (*policy.StoredConfig, error) {
	draft, _, err := m.cloneStored(m.policy)
	if err != nil {
		return nil, err
	}
	if draft.TransferPolicy == nil {
		return nil, fmt.Errorf("transfer policy is not initialized")
	}
	if _, ok := draft.TransferPolicy.AssetSets[name]; !ok {
		return nil, fmt.Errorf("asset set %s no longer exists", name)
	}
	delete(draft.TransferPolicy.AssetSets, name)
	if len(draft.TransferPolicy.AssetSets) == 0 {
		draft.TransferPolicy.AssetSets = nil
	}
	return draft, nil
}

func (m Model) guardGroupToEditFields(group transferGuardGroup) []routeEditField {
	return []routeEditField{
		{key: "id", label: "Name", value: group.ID},
		{key: "description", label: "Description", value: group.Description},
		{key: "enabled", label: "Enabled", value: boolValueWithDefault(group.Enabled, true)},
		{key: "networks", label: "Networks", value: joinTerms(group.Networks)},
		{key: "sources", label: "Sources", value: joinTerms(group.Sources)},
		{key: "destinations", label: "Destinations", value: joinTerms(group.Destinations)},
		{key: "close_allow", label: "Close Allow", value: boolValueWithDefault(group.CloseAllow, false)},
	}
}

func (m Model) guardGroupToEditAssetRows(group transferGuardGroup) []routeEditAssetRow {
	rows := make([]routeEditAssetRow, 0, len(group.AssetRows))
	for _, row := range group.AssetRows {
		rows = append(rows, routeEditAssetRow{
			routeIndex:  row.RouteIndex,
			routeID:     row.RouteID,
			asset:       row.Asset,
			reviewAbove: m.formatOptionalGuardAmount(row.ReviewAbove, row.Asset, group.Networks),
			rejectAbove: m.formatOptionalGuardAmount(row.RejectAbove, row.Asset, group.Networks),
		})
	}
	return rows
}

func (m *Model) backspaceEditField() {
	value, ok := m.currentEditValue()
	if !ok || value == "" {
		return
	}
	runes := []rune(value)
	m.setCurrentEditValue(string(runes[:len(runes)-1]))
}

func (m *Model) clearEditField() {
	m.setCurrentEditValue("")
}

func (m Model) currentEditField() *routeEditField {
	if m.editCursor < 0 || m.editCursor >= len(m.editFields) {
		return nil
	}
	return &m.editFields[m.editCursor]
}

func (m Model) routeEditItemCount() int {
	return len(m.editFields) + len(m.editAssetRows)*routeEditAssetColumnCount
}

func (m Model) currentAssetCell() (int, string, bool) {
	cell := m.editCursor - len(m.editFields)
	if cell < 0 {
		return 0, "", false
	}
	row := cell / routeEditAssetColumnCount
	col := cell % routeEditAssetColumnCount
	if row < 0 || row >= len(m.editAssetRows) {
		return 0, "", false
	}
	switch col {
	case 0:
		return row, "asset", true
	case 1:
		return row, "review_above", true
	default:
		return row, "reject_above", true
	}
}

func (m Model) currentEditKey() string {
	if field := m.currentEditField(); field != nil {
		return field.key
	}
	_, col, ok := m.currentAssetCell()
	if !ok {
		return ""
	}
	return col
}

func (m Model) currentEditLabel() string {
	if field := m.currentEditField(); field != nil {
		return field.label
	}
	row, col, ok := m.currentAssetCell()
	if !ok {
		return "Field"
	}
	switch col {
	case "asset":
		return fmt.Sprintf("Asset %d", row+1)
	case "review_above":
		return fmt.Sprintf("Review Above %d", row+1)
	default:
		return fmt.Sprintf("Reject Above %d", row+1)
	}
}

func (m Model) currentEditValue() (string, bool) {
	if field := m.currentEditField(); field != nil {
		return field.value, true
	}
	row, col, ok := m.currentAssetCell()
	if !ok {
		return "", false
	}
	switch col {
	case "asset":
		return m.editAssetRows[row].asset, true
	case "review_above":
		return m.editAssetRows[row].reviewAbove, true
	default:
		return m.editAssetRows[row].rejectAbove, true
	}
}

func (m *Model) setCurrentEditValue(value string) {
	if m.editCursor >= 0 && m.editCursor < len(m.editFields) {
		m.editFields[m.editCursor].value = value
		return
	}
	row, col, ok := m.currentAssetCell()
	if !ok {
		return
	}
	switch col {
	case "asset":
		m.editAssetRows[row].asset = value
	case "review_above":
		m.editAssetRows[row].reviewAbove = value
	default:
		m.editAssetRows[row].rejectAbove = value
	}
}

func (m *Model) addEditAssetRow() {
	insertAt := len(m.editAssetRows)
	if row, _, ok := m.currentAssetCell(); ok {
		insertAt = row + 1
	}
	newRow := routeEditAssetRow{asset: "algo"}
	m.editAssetRows = append(m.editAssetRows, routeEditAssetRow{})
	copy(m.editAssetRows[insertAt+1:], m.editAssetRows[insertAt:])
	m.editAssetRows[insertAt] = newRow
	m.editCursor = len(m.editFields) + insertAt*routeEditAssetColumnCount
	m.status = "added asset row"
	m.err = ""
}

func (m *Model) deleteCurrentEditAssetRow() {
	row, _, ok := m.currentAssetCell()
	if !ok {
		m.status = "select an asset row to delete"
		return
	}
	if len(m.editAssetRows) <= 1 {
		m.status = "guard requires at least one asset row"
		return
	}
	copy(m.editAssetRows[row:], m.editAssetRows[row+1:])
	m.editAssetRows = m.editAssetRows[:len(m.editAssetRows)-1]
	if m.editCursor >= m.routeEditItemCount() {
		m.editCursor = m.routeEditItemCount() - 1
	}
	m.status = "deleted asset row"
	m.err = ""
}

func (m Model) assetSetEditItemCount() int {
	return 1 + len(m.editAssetSetRows)*2
}

func (m *Model) moveAssetSetEditCursor(delta int) {
	count := m.assetSetEditItemCount()
	if count <= 0 {
		m.editCursor = 0
		return
	}
	m.editCursor += delta
	if m.editCursor < 0 {
		m.editCursor = 0
	}
	if m.editCursor >= count {
		m.editCursor = count - 1
	}
}

func (m Model) currentAssetSetCell() (int, string, bool) {
	if m.editCursor == 0 {
		return 0, "name", true
	}
	cell := m.editCursor - 1
	row := cell / 2
	col := cell % 2
	if row < 0 || row >= len(m.editAssetSetRows) {
		return 0, "", false
	}
	if col == 0 {
		return row, "network", true
	}
	return row, "asa_ids", true
}

func (m Model) currentAssetSetEditKey() string {
	_, key, ok := m.currentAssetSetCell()
	if !ok {
		return ""
	}
	return key
}

func (m Model) currentAssetSetEditLabel() string {
	row, key, ok := m.currentAssetSetCell()
	if !ok {
		return "Field"
	}
	switch key {
	case "name":
		return "Name"
	case "network":
		return fmt.Sprintf("Network %d", row+1)
	default:
		return fmt.Sprintf("ASA IDs %d", row+1)
	}
}

func (m Model) currentAssetSetEditValue() (string, bool) {
	row, key, ok := m.currentAssetSetCell()
	if !ok {
		return "", false
	}
	switch key {
	case "name":
		return m.editAssetSetName, true
	case "network":
		return m.editAssetSetRows[row].Network, true
	default:
		return m.editAssetSetRows[row].ASAIDs, true
	}
}

func (m *Model) setCurrentAssetSetEditValue(value string) {
	row, key, ok := m.currentAssetSetCell()
	if !ok {
		return
	}
	switch key {
	case "name":
		m.editAssetSetName = value
	case "network":
		m.editAssetSetRows[row].Network = value
	case "asa_ids":
		m.editAssetSetRows[row].ASAIDs = value
	}
}

func (m Model) openAssetSetFieldEditor() Model {
	if m.currentAssetSetEditKey() == "" {
		m.status = "select a field to edit"
		return m
	}
	m.screen = screenAssetSetTextEdit
	m.status = "editing " + strings.ToLower(m.currentAssetSetEditLabel())
	m.err = ""
	return m
}

func (m *Model) addAssetSetNetworkRow() {
	insertAt := len(m.editAssetSetRows)
	if row, key, ok := m.currentAssetSetCell(); ok && key != "name" {
		insertAt = row + 1
	}
	m.editAssetSetRows = append(m.editAssetSetRows, assetSetEditRow{})
	copy(m.editAssetSetRows[insertAt+1:], m.editAssetSetRows[insertAt:])
	m.editAssetSetRows[insertAt] = assetSetEditRow{Network: "testnet"}
	m.editCursor = 1 + insertAt*2
	m.status = "added network row"
	m.err = ""
}

func (m *Model) deleteCurrentAssetSetNetworkRow() {
	row, key, ok := m.currentAssetSetCell()
	if !ok || key == "name" {
		m.status = "select a network row to delete"
		return
	}
	if len(m.editAssetSetRows) <= 1 {
		m.status = "asset set requires at least one network row"
		return
	}
	copy(m.editAssetSetRows[row:], m.editAssetSetRows[row+1:])
	m.editAssetSetRows = m.editAssetSetRows[:len(m.editAssetSetRows)-1]
	if m.editCursor >= m.assetSetEditItemCount() {
		m.editCursor = m.assetSetEditItemCount() - 1
	}
	m.status = "deleted network row"
	m.err = ""
}

func (m Model) currentRouteListField() *routeEditField {
	field := m.currentEditField()
	if field == nil || !isRouteListField(field.key) {
		return nil
	}
	return field
}

func (m Model) currentBlockedDestinationsListField() *routeEditField {
	if m.screen != screenBlockedDestinationsEdit || len(m.blockedDestinationsFields) == 0 {
		return nil
	}
	return &m.blockedDestinationsFields[0]
}

func (m Model) currentListEditField() *routeEditField {
	switch m.screen {
	case screenBlockedDestinationsEdit:
		return m.currentBlockedDestinationsListField()
	default:
		return m.currentRouteListField()
	}
}

func (m Model) openRouteFieldEditor() Model {
	key := m.currentEditKey()
	if key == "" {
		m.status = "select a field to edit"
		return m
	}
	switch routeEditorKind(key) {
	case "list":
		return m.openRouteListEditor()
	case "choice":
		return m.openRouteChoiceEditor()
	default:
		return m.openRouteTextEditor()
	}
}

func (m Model) openRouteListEditor() Model {
	field := m.currentRouteListField()
	if field == nil {
		m.status = "select a list field to edit"
		return m
	}
	m.screen = screenRouteListEdit
	m.editListOffset = 0
	field.value = routeListStorageValue(parseCSV(field.value))
	if field.value != "" {
		field.value += "\n"
	}
	m.status = "editing " + strings.ToLower(field.label)
	m.err = ""
	return m
}

func (m Model) openRouteTextEditor() Model {
	if m.currentEditKey() == "" {
		m.status = "select a text field to edit"
		return m
	}
	m.screen = screenRouteTextEdit
	m.status = "editing " + strings.ToLower(m.currentEditLabel())
	m.err = ""
	return m
}

func (m Model) openRouteChoiceEditor() Model {
	key := m.currentEditKey()
	choices := routeChoiceOptionsForKey(key)
	if key == "" || len(choices) == 0 {
		m.status = "select a choice field to edit"
		return m
	}
	m.screen = screenRouteChoiceEdit
	m.editChoiceCursor = 0
	current, _ := m.currentEditValue()
	current = strings.TrimSpace(current)
	for i, choice := range choices {
		if choice == current {
			m.editChoiceCursor = i
			break
		}
	}
	m.status = "choosing " + strings.ToLower(m.currentEditLabel())
	m.err = ""
	return m
}

func (m *Model) appendRouteListInput(input string) {
	field := m.currentListEditField()
	if field == nil {
		return
	}
	value := routeListEditValue(field.value)
	for _, r := range input {
		switch {
		case r == '\r':
			continue
		case r == '\n' || r == ',' || r == ' ':
			value = appendTermSeparator(value)
		case isRouteListRune(r):
			value += string(r)
		}
	}
	field.value = value
	m.ensureRouteListInputVisible()
}

func (m *Model) backspaceRouteListInput() {
	field := m.currentListEditField()
	if field == nil {
		return
	}
	value := routeListEditValue(field.value)
	if value == "" {
		field.value = ""
		m.editListOffset = 0
		return
	}
	runes := []rune(value)
	field.value = string(runes[:len(runes)-1])
	m.ensureRouteListInputVisible()
}

func (m *Model) clearRouteListInput() {
	field := m.currentListEditField()
	if field == nil {
		return
	}
	field.value = ""
	m.editListOffset = 0
}

func (m *Model) ensureRouteListInputVisible() {
	m.editListOffset = m.routeListMaxOffset()
}

func (m Model) routeListMaxOffset() int {
	field := m.currentListEditField()
	if field == nil {
		return 0
	}
	return maxOffsetForLines(routeListLines(field.value), m.routeListVisibleLines())
}

func (m Model) routeListVisibleLines() int {
	if m.height <= 0 {
		return 6
	}
	visible := m.height - m.appChromeLines() - m.routeListChromeLines()
	if visible < 3 {
		return 3
	}
	if visible > 8 {
		return 8
	}
	return visible
}

func (m Model) routeListChromeLines() int {
	// Popup title, spacer, entries, hint, spacer, input frame, spacer, help,
	// and popup border/padding.
	return 9 + inputActiveStyle.GetVerticalFrameSize() + popupStyle.GetVerticalFrameSize()
}

func (m Model) routeListInputWidth() int {
	width := m.popupBodyWidth(80) - inputActiveStyle.GetHorizontalFrameSize()
	if width < 20 {
		return 20
	}
	return width
}

func (m *Model) appendRouteTextInput(input string) {
	key := m.currentEditKey()
	value, ok := m.currentEditValue()
	if !ok {
		return
	}
	for _, r := range input {
		if isRouteTextRune(key, r) {
			value += string(r)
		}
	}
	m.setCurrentEditValue(value)
}

func (m Model) routeTextInputWidth() int {
	width := m.popupBodyWidth(80) - inputActiveStyle.GetHorizontalFrameSize()
	if width < 20 {
		return 20
	}
	return width
}

func (m Model) routeTextDisplayValue(value string) string {
	width := m.routeTextInputWidth()
	if width < 1 {
		return ""
	}
	cursor := "_"
	runes := []rune(value)
	if len(runes) >= width {
		runes = runes[len(runes)-width+1:]
	}
	return string(runes) + cursor
}

func (m Model) writePathDisplayValue() string {
	return m.routeTextDisplayValue(m.writePath)
}

func assetSetEditDisplayValue(key, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return ellipsize(value, 48)
}

func (m *Model) appendAssetSetTextInput(input string) {
	key := m.currentAssetSetEditKey()
	value, ok := m.currentAssetSetEditValue()
	if !ok {
		return
	}
	for _, r := range input {
		if isAssetSetTextRune(key, r) {
			value += string(r)
		}
	}
	m.setCurrentAssetSetEditValue(value)
}

func (m *Model) backspaceAssetSetTextInput() {
	value, ok := m.currentAssetSetEditValue()
	if !ok || value == "" {
		return
	}
	runes := []rune(value)
	m.setCurrentAssetSetEditValue(string(runes[:len(runes)-1]))
}

func (m Model) assetSetTextDisplayValue(value string) string {
	return m.routeTextDisplayValue(value)
}

func (m Model) assetSetTextHint(key string) string {
	switch key {
	case "name":
		return "Asset set name. Use lowercase letters, digits, underscore, or hyphen; routes reference it as @name."
	case "network":
		return "Network context token such as mainnet, testnet, or localnet. * is not valid for asset sets."
	case "asa_ids":
		return "Comma-separated ASA IDs. Use numeric IDs or asa:<id>."
	default:
		return "Enter a value."
	}
}

func routeEditFieldDisplayValue(field routeEditField) string {
	if isRouteListField(field.key) {
		terms := parseCSV(field.value)
		if len(terms) == 1 {
			return ellipsize(terms[0], 48)
		}
		return fmt.Sprintf("%d", len(terms))
	}
	return ellipsize(field.value, 48)
}

func routeEditorKind(key string) string {
	switch key {
	case "networks", "sources", "destinations":
		return "list"
	case "enabled", "close_allow":
		return "choice"
	default:
		return "text"
	}
}

func isRouteListField(key string) bool {
	return routeEditorKind(key) == "list"
}

func routeChoiceOptionsForKey(key string) []string {
	if key == "" {
		return nil
	}
	switch key {
	case "enabled", "close_allow":
		return []string{"true", "false"}
	default:
		return nil
	}
}

func routeListHint(key string) string {
	switch key {
	case "networks":
		return "One entry per line. Use network context tokens or *."
	case "sources":
		return "One entry per line. Supports addresses, @address_set, or *."
	case "destinations":
		return "One entry per line. Supports addresses, @address_set, self, or *."
	default:
		return "One entry per line."
	}
}

func (m Model) routeTextHint(key string) string {
	switch key {
	case "id":
		return "Route ID. Use lowercase letters, digits, underscore, or hyphen."
	case "description":
		return "Optional operator-facing note."
	case "asset":
		hint := "Use algo, an ASA ID, asa:<id>, cached symbol, asset set name, or *."
		if sets := m.assetSetReferenceSummary(); sets != "" {
			hint += " Defined asset sets: " + sets + "."
		}
		return hint
	case "review_above", "reject_above":
		return m.guardAmountHint(m.currentEditAmountAsset(), parseCSV(routeEditFieldValue(m.editFields, "networks")))
	default:
		return "Enter a value."
	}
}

func (m Model) currentEditAmountAsset() string {
	row, _, ok := m.currentAssetCell()
	if ok && row >= 0 && row < len(m.editAssetRows) {
		return m.editAssetRows[row].asset
	}
	return "algo"
}

func routeEditFieldValue(fields []routeEditField, key string) string {
	for _, field := range fields {
		if field.key == key {
			return field.value
		}
	}
	return ""
}

func routeListStorageValue(terms []string) string {
	return strings.Join(terms, "\n")
}

func routeListEditValue(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	if strings.TrimSpace(value) == "-" {
		return ""
	}
	if strings.Contains(value, "\n") {
		return value
	}
	return routeListStorageValue(parseCSV(value))
}

func routeListLines(value string) []string {
	lines := strings.Split(routeListEditValue(value), "\n")
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func appendTermSeparator(value string) string {
	value = strings.TrimRight(value, "\n")
	if value == "" {
		return value
	}
	return value + "\n"
}

func isRouteListRune(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '@' || r == '_' || r == '-' || r == '*' || r == ':'
}

func isRouteTextRune(key string, r rune) bool {
	switch key {
	case "review_above", "reject_above":
		return (r >= '0' && r <= '9') || r == '.'
	case "id":
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-'
	default:
		return r >= 32 && r <= 126
	}
}

func isAssetSetTextRune(key string, r rune) bool {
	switch key {
	case "name":
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-'
	case "network":
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-'
	case "asa_ids":
		return (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == ':' || r == ',' || r == ' '
	default:
		return r >= 32 && r <= 126
	}
}

func maxOffsetForLines(lines []string, visibleLines int) int {
	if visibleLines < 1 {
		visibleLines = 1
	}
	maxOffset := len(lines) - visibleLines
	if maxOffset < 0 {
		return 0
	}
	return maxOffset
}

func (m Model) applyAssetSetEdit() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.editAssetSetName)
	if err := validateAssetSetName(name); err != nil {
		m.err = err.Error()
		m.status = "asset set parse failed"
		return m, nil
	}
	set, err := editRowsToAssetSet(m.editAssetSetRows)
	if err != nil {
		m.err = err.Error()
		m.status = "asset set parse failed"
		return m, nil
	}
	draft, err := m.policyWithEditedAssetSet(m.editAssetSetOriginalName, name, set)
	if err != nil {
		m.err = err.Error()
		m.status = "asset set save failed"
		return m, nil
	}
	m.busy = true
	m.formApplyToken++
	token := m.formApplyToken
	oldName := m.editAssetSetOriginalName
	m.err = ""
	m.status = "validating asset set"
	return m, func() tea.Msg {
		return assetSetApplyResultMsg{
			token:   token,
			oldName: oldName,
			name:    name,
			set:     set,
			err:     m.store.Validate(context.Background(), draft),
		}
	}
}

func (m Model) deleteSelectedAssetSetConfirmed() (tea.Model, tea.Cmd) {
	name := strings.TrimSpace(m.deleteAssetSetName)
	if name == "" {
		m.screen = screenAssetSets
		m.status = "asset set no longer exists"
		return m, nil
	}
	draft, err := m.policyWithDeletedAssetSet(name)
	if err != nil {
		m.err = err.Error()
		m.status = "asset set delete failed"
		m.screen = screenAssetSets
		return m, nil
	}
	m.busy = true
	m.formApplyToken++
	token := m.formApplyToken
	m.err = ""
	m.status = "validating asset set delete"
	return m, func() tea.Msg {
		return assetSetDeleteResultMsg{
			token: token,
			name:  name,
			err:   m.store.Validate(context.Background(), draft),
		}
	}
}

func (m Model) applyRouteEdit() (tea.Model, tea.Cmd) {
	routes, err := m.editFieldsToGuardGroupRoutes()
	if err != nil {
		m.err = err.Error()
		m.status = "guard parse failed"
		return m, nil
	}
	draft, err := m.policyWithEditedGuardGroup(routes)
	if err != nil {
		m.err = err.Error()
		m.status = "guard save failed"
		return m, nil
	}
	m.busy = true
	m.formApplyToken++
	token := m.formApplyToken
	m.err = ""
	m.status = "validating guard"
	return m, func() tea.Msg {
		return routeApplyResultMsg{token: token, groupIndex: m.editGroupIndex, routes: routes, err: m.store.Validate(context.Background(), draft)}
	}
}

func (m Model) editFieldsToGuardGroupRoutes() ([]policy.StoredTransferRoute, error) {
	values := editFieldValues(m.editFields)
	guardName := strings.TrimSpace(values["id"])
	if guardName == "" {
		return nil, fmt.Errorf("name is required")
	}
	enabled, err := parseOptionalBool(values["enabled"])
	if err != nil {
		return nil, fmt.Errorf("enabled: %w", err)
	}
	closeAllow, err := parseOptionalBool(values["close_allow"])
	if err != nil {
		return nil, fmt.Errorf("close_allow: %w", err)
	}
	networks := parseCSV(values["networks"])
	group := transferGuardGroup{
		Index:        m.editGroupIndex,
		ID:           guardName,
		Description:  strings.TrimSpace(values["description"]),
		Enabled:      enabled,
		Networks:     networks,
		Sources:      parseCSV(values["sources"]),
		Destinations: parseCSV(values["destinations"]),
		CloseAllow:   closeAllow,
	}
	if len(m.editAssetRows) == 0 {
		return nil, fmt.Errorf("at least one asset row is required")
	}

	seen := m.routeIDSetExcludingEditedGroup()
	for i, editRow := range m.editAssetRows {
		asset, err := m.normalizeGuardAsset(editRow.asset, networks)
		if err != nil {
			return nil, fmt.Errorf("asset row %d asset: %w", i+1, err)
		}
		if asset == "" {
			return nil, fmt.Errorf("asset row %d asset is required", i+1)
		}
		reviewAbove, err := m.parseOptionalGuardAmount(editRow.reviewAbove, asset, networks)
		if err != nil {
			return nil, fmt.Errorf("asset row %d review_above: %w", i+1, err)
		}
		rejectAbove, err := m.parseOptionalGuardAmount(editRow.rejectAbove, asset, networks)
		if err != nil {
			return nil, fmt.Errorf("asset row %d reject_above: %w", i+1, err)
		}
		id := m.editedAssetRouteID(guardName, asset, editRow)
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("asset row %d route id %q is already in use", i+1, id)
		}
		seen[id] = struct{}{}
		group.AssetRows = append(group.AssetRows, transferGuardAssetRow{
			RouteIndex:  editRow.routeIndex,
			RouteID:     id,
			Asset:       asset,
			ReviewAbove: reviewAbove,
			RejectAbove: rejectAbove,
		})
	}
	return guardGroupToRoutes(group, m.routes())
}

func (m Model) editedAssetRouteID(guardName, asset string, editRow routeEditAssetRow) string {
	routes := m.routes()
	if editRow.routeIndex >= 0 && editRow.routeIndex < len(routes) {
		return guardRouteIDForExisting(guardName, asset, &routes[editRow.routeIndex])
	}
	if editRow.routeID != "" {
		return editRow.routeID
	}
	return guardRouteID(guardName, asset)
}

func editFieldValues(fields []routeEditField) map[string]string {
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		values[field.key] = strings.TrimSpace(field.value)
	}
	return values
}

func (m Model) routeIDSetExcludingEditedGroup() map[string]struct{} {
	routes := m.routes()
	seen := routeIDSet(routes)
	groups := transferGuardGroups(routes)
	if m.editGroupIndex < 0 || m.editGroupIndex >= len(groups) {
		return seen
	}
	for _, index := range groups[m.editGroupIndex].RouteIndexes {
		if index >= 0 && index < len(routes) {
			delete(seen, routes[index].ID)
		}
	}
	return seen
}

func (m Model) policyWithEditedGuardGroup(routes []policy.StoredTransferRoute) (*policy.StoredConfig, error) {
	draft, _, err := m.cloneStored(m.policy)
	if err != nil {
		return nil, err
	}
	if draft.TransferPolicy == nil {
		return nil, fmt.Errorf("transfer policy is not initialized")
	}
	groups := transferGuardGroups(draft.TransferPolicy.Routes)
	if m.editGroupIndex < 0 || m.editGroupIndex >= len(groups) {
		return nil, fmt.Errorf("route index is no longer valid")
	}
	start, end := guardGroupRouteRange(groups[m.editGroupIndex])
	updated := removeRouteBlock(draft.TransferPolicy.Routes, start, end)
	draft.TransferPolicy.Routes = insertRoutes(updated, start, routes)
	draft.TransferPolicy.RoutesSet = true
	return draft, nil
}

func parseCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseOptionalBool(raw string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "default", "inherit", "-":
		return nil, nil
	case "true", "yes", "y", "1":
		v := true
		return &v, nil
	case "false", "no", "n", "0":
		v := false
		return &v, nil
	default:
		return nil, fmt.Errorf("expected default, true, or false")
	}
}

func parseRequiredBool(raw string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "y", "1":
		v := true
		return &v, nil
	case "false", "no", "n", "0":
		v := false
		return &v, nil
	default:
		return nil, fmt.Errorf("expected true or false")
	}
}

func (m Model) cloneGuardGroup(group transferGuardGroup) []policy.StoredTransferRoute {
	clone := group
	clone.ID = m.uniqueGuardName(group.ID+"_copy", guardGroupAssets(group))
	clone.Description = ""
	clone.RouteIndexes = nil
	for i := range clone.AssetRows {
		clone.AssetRows[i].RouteIndex = -1
		clone.AssetRows[i].RouteID = ""
	}
	routes, err := guardGroupToRoutes(clone, m.routes())
	if err != nil {
		return nil
	}
	return routes
}

func (m Model) uniqueGuardName(base string, assets []string) string {
	return uniqueGuardNameWithSeen(base, assets, routeIDSet(m.routes()))
}

func uniqueGuardNameWithSeen(base string, assets []string, seen map[string]struct{}) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "guard"
	}
	if len(assets) == 0 {
		assets = []string{"asset"}
	}
	if guardRouteIDsAvailable(base, assets, seen) {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		if guardRouteIDsAvailable(candidate, assets, seen) {
			return candidate
		}
	}
}

func guardRouteIDsAvailable(guardName string, assets []string, seen map[string]struct{}) bool {
	for _, asset := range assets {
		if _, ok := seen[guardRouteID(guardName, asset)]; ok {
			return false
		}
	}
	return true
}

func guardGroupAssets(group transferGuardGroup) []string {
	assets := make([]string, 0, len(group.AssetRows))
	for _, row := range group.AssetRows {
		assets = append(assets, row.Asset)
	}
	return assets
}

func (m Model) uniqueAssetSetName(base string) string {
	seen := make(map[string]struct{})
	if m.policy != nil && m.policy.TransferPolicy != nil {
		for name := range m.policy.TransferPolicy.AssetSets {
			seen[name] = struct{}{}
		}
	}
	return uniqueNameWithSeen(base, "asset_set", seen)
}

func uniqueNameWithSeen(base, fallback string, seen map[string]struct{}) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = fallback
	}
	if _, ok := seen[base]; !ok {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		if _, ok := seen[candidate]; !ok {
			return candidate
		}
	}
}

func routeIDSet(routes []policy.StoredTransferRoute) map[string]struct{} {
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		seen[route.ID] = struct{}{}
	}
	return seen
}

func cloneRoute(route policy.StoredTransferRoute) policy.StoredTransferRoute {
	out := route
	out.Networks = append([]string(nil), route.Networks...)
	out.Sources = append([]string(nil), route.Sources...)
	out.AssetSources = append([]string(nil), route.AssetSources...)
	out.Assets = append([]policy.StoredAssetTerm(nil), route.Assets...)
	out.Destinations = append([]string(nil), route.Destinations...)
	if route.Limits != nil {
		limits := *route.Limits
		if route.Limits.ReviewAbove != nil {
			v := *route.Limits.ReviewAbove
			limits.ReviewAbove = &v
		}
		if route.Limits.RejectAbove != nil {
			v := *route.Limits.RejectAbove
			limits.RejectAbove = &v
		}
		out.Limits = &limits
	}
	if route.LimitsByNetwork != nil {
		out.LimitsByNetwork = make(map[string]policy.StoredAmountLimits, len(route.LimitsByNetwork))
		for network, limits := range route.LimitsByNetwork {
			cp := limits
			if limits.ReviewAbove != nil {
				v := *limits.ReviewAbove
				cp.ReviewAbove = &v
			}
			if limits.RejectAbove != nil {
				v := *limits.RejectAbove
				cp.RejectAbove = &v
			}
			out.LimitsByNetwork[network] = cp
		}
	}
	if route.Enabled != nil {
		v := *route.Enabled
		out.Enabled = &v
	}
	if route.Close.Allow != nil {
		v := *route.Close.Allow
		out.Close.Allow = &v
	}
	if route.Clawback.Allow != nil {
		v := *route.Clawback.Allow
		out.Clawback.Allow = &v
	}
	return out
}

func insertRoutes(routes []policy.StoredTransferRoute, index int, inserted []policy.StoredTransferRoute) []policy.StoredTransferRoute {
	if index < 0 {
		index = 0
	}
	if index > len(routes) {
		index = len(routes)
	}
	if len(inserted) == 0 {
		return routes
	}
	routes = append(routes, inserted...)
	copy(routes[index+len(inserted):], routes[index:])
	copy(routes[index:], inserted)
	return routes
}

func removeRouteBlock(routes []policy.StoredTransferRoute, start, end int) []policy.StoredTransferRoute {
	if start < 0 {
		start = 0
	}
	if end > len(routes) {
		end = len(routes)
	}
	if start >= end {
		return routes
	}
	copy(routes[start:], routes[end:])
	return routes[:len(routes)-(end-start)]
}

func guardGroupRouteRange(group transferGuardGroup) (int, int) {
	if len(group.RouteIndexes) == 0 {
		return 0, 0
	}
	start := group.RouteIndexes[0]
	end := group.RouteIndexes[len(group.RouteIndexes)-1] + 1
	return start, end
}

func moveGuardGroupUp(routes []policy.StoredTransferRoute, groups []transferGuardGroup, index int) []policy.StoredTransferRoute {
	if index <= 0 || index >= len(groups) {
		return routes
	}
	prevStart, _ := guardGroupRouteRange(groups[index-1])
	start, end := guardGroupRouteRange(groups[index])
	if prevStart < 0 || start < prevStart || end > len(routes) {
		return routes
	}
	out := make([]policy.StoredTransferRoute, 0, len(routes))
	out = append(out, routes[:prevStart]...)
	out = append(out, routes[start:end]...)
	out = append(out, routes[prevStart:start]...)
	out = append(out, routes[end:]...)
	return out
}

func moveGuardGroupDown(routes []policy.StoredTransferRoute, groups []transferGuardGroup, index int) []policy.StoredTransferRoute {
	if index < 0 || index >= len(groups)-1 {
		return routes
	}
	start, end := guardGroupRouteRange(groups[index])
	_, nextEnd := guardGroupRouteRange(groups[index+1])
	if start < 0 || end < start || nextEnd > len(routes) {
		return routes
	}
	out := make([]policy.StoredTransferRoute, 0, len(routes))
	out = append(out, routes[:start]...)
	out = append(out, routes[end:nextEnd]...)
	out = append(out, routes[start:end]...)
	out = append(out, routes[nextEnd:]...)
	return out
}

func (m Model) routes() []policy.StoredTransferRoute {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return nil
	}
	return m.policy.TransferPolicy.Routes
}

func (m Model) assetSetRows() []assetSetRow {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return nil
	}
	return transferAssetSetRows(m.policy.TransferPolicy.AssetSets)
}

func (m Model) matchingAssetSetName(raw string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" || strings.HasPrefix(name, "@") {
		return "", false
	}
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return "", false
	}
	_, ok := m.policy.TransferPolicy.AssetSets[name]
	return name, ok
}

func (m Model) assetSetReferenceSummary() string {
	rows := m.assetSetRows()
	if len(rows) == 0 {
		return ""
	}
	limit := len(rows)
	if limit > 4 {
		limit = 4
	}
	names := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		names = append(names, rows[i].Name)
	}
	if len(rows) > limit {
		names = append(names, fmt.Sprintf("+%d more", len(rows)-limit))
	}
	return strings.Join(names, ", ")
}

func (m *Model) cycleSelectedGuardGroupEnabled(group transferGuardGroup) {
	if m.policy == nil || m.policy.TransferPolicy == nil {
		return
	}
	next := nextBoolOverride(group.Enabled, true)
	for _, index := range group.RouteIndexes {
		if index < 0 || index >= len(m.policy.TransferPolicy.Routes) {
			continue
		}
		m.policy.TransferPolicy.Routes[index].Enabled = cloneBoolPtr(next)
	}
	m.policy.TransferPolicy.RoutesSet = true
}

func (m Model) selectedGuardGroupEnabled(group transferGuardGroup) *bool {
	if m.policy == nil || m.policy.TransferPolicy == nil || len(group.RouteIndexes) == 0 {
		return nil
	}
	index := group.RouteIndexes[0]
	if index < 0 || index >= len(m.policy.TransferPolicy.Routes) {
		return nil
	}
	return m.policy.TransferPolicy.Routes[index].Enabled
}

func nextBoolOverride(current *bool, defaultValue bool) *bool {
	currentValue := defaultValue
	if current != nil {
		currentValue = *current
	}
	next := !currentValue
	if next == defaultValue {
		return nil
	}
	v := next
	return &v
}

func boolValueWithDefault(v *bool, defaultValue bool) string {
	if v == nil {
		return fmt.Sprintf("%t", defaultValue)
	}
	return fmt.Sprintf("%t", *v)
}

func joinTerms(terms []string) string {
	if len(terms) == 0 {
		return "-"
	}
	return strings.Join(terms, ",")
}

func joinAssetTerms(terms []policy.StoredAssetTerm) string {
	if len(terms) == 0 {
		return "-"
	}
	raw := make([]string, 0, len(terms))
	for _, term := range terms {
		raw = append(raw, term.Raw)
	}
	return strings.Join(raw, ",")
}

func (m Model) cloneStored(stored *policy.StoredConfig) (*policy.StoredConfig, []byte, error) {
	return cloneStoredForTarget(stored, m.target)
}

func cloneStoredForTarget(stored *policy.StoredConfig, target policyeditor.Target) (*policy.StoredConfig, []byte, error) {
	data, err := marshalStoredForTarget(stored, target)
	if err != nil {
		return nil, nil, err
	}
	cp, err := target.Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return cp, data, nil
}

func (m Model) marshalStored(stored *policy.StoredConfig) ([]byte, error) {
	return marshalStoredForTarget(stored, m.target)
}

func marshalStored(stored *policy.StoredConfig) ([]byte, error) {
	return marshalStoredForTarget(stored, policyeditor.TargetSigner)
}

func marshalStoredForTarget(stored *policy.StoredConfig, target policyeditor.Target) ([]byte, error) {
	data, err := target.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal stored %s: %w", target.StatusNoun(), err)
	}
	return data, nil
}
