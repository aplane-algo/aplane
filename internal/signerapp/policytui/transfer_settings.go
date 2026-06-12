// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

// Transfer-settings and blocked-destinations screens and their
// apply paths.

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

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
	return []routeEditField{
		{key: "enabled", label: "Enabled", value: enabled},
		{key: "on_no_route", label: "On No Route", value: onNoRoute},
		{key: "close_on_no_route", label: "Close On No Route", value: closeOnNoRoute},
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
	case "enabled", "on_no_route", "close_on_no_route":
		return "choice"
	default:
		return "text"
	}
}

func transferSettingsChoiceOptionsForKey(key string) []string {
	switch key {
	case "enabled":
		return []string{"true", "false"}
	case "on_no_route", "close_on_no_route":
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
	tp.SchemaVersion = 1
	tp.Enabled = enabled
	tp.OnNoRoute = onNoRoute
	tp.CloseOnNoRoute = closeOnNoRoute
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
	return &policy.StoredTransferPolicy{
		SchemaVersion:  1,
		Enabled:        &enabled,
		OnNoRoute:      &onNoRoute,
		CloseOnNoRoute: &closeOnNoRoute,
		RoutesSet:      true,
	}
}

func (m Model) currentBlockedDestinationsListField() *routeEditField {
	if m.screen != screenBlockedDestinationsEdit || len(m.blockedDestinationsFields) == 0 {
		return nil
	}
	return &m.blockedDestinationsFields[0]
}
