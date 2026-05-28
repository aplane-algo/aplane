// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/adminproto"
	apconfig "github.com/aplane-algo/aplane/internal/config"
)

type policyASAEntry struct {
	AssetID      uint64
	ReviewAmount string
	MaxAmount    string
	Meta         *ASAMetadataInfo
}

func (m Model) handlePolicyPanelKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.policyRows()

	if m.policyEditingRow >= 0 {
		switch msg.String() {
		case "esc":
			m.policyEditingRow = -1
			m.policyEditValue = ""
		case "enter":
			if m.policyEditingRow < len(rows) {
				row := rows[m.policyEditingRow]
				value := strings.TrimSpace(m.policyEditValue)
				m.policyEditingRow = -1
				if err := validatePolicySettingValue(row.key, value); err != nil {
					m.lastError = err.Error()
					return m, nil
				}
				return m, m.sendUpdatePolicySettingCmd(row.key, value)
			}
			m.policyEditingRow = -1
		case "backspace":
			if len(m.policyEditValue) > 0 {
				m.policyEditValue = m.policyEditValue[:len(m.policyEditValue)-1]
			}
		default:
			if len(msg.String()) == 1 {
				m.policyEditValue += msg.String()
			}
		}
		return m, nil
	}

	switch msg.String() {
	case "esc", "q":
		m.viewState = ViewAdminPanel
		return m, tea.Batch(m.sendGetAdminSettingsCmd(), m.waitForMessageCmd(), adminRefreshTickCmd())
	case "up", "k":
		if m.policySelectedRow > 0 {
			m.policySelectedRow--
		}
	case "down", "j":
		if m.policySelectedRow < len(rows)-1 {
			m.policySelectedRow++
		}
	case "enter":
		if m.policySelectedRow < len(rows) {
			row := rows[m.policySelectedRow]
			if !row.editable {
				return m, nil
			}
			if row.action == "edit_asa_limits" || row.action == "edit_transfer_guards" {
				m = m.startPolicyASAModal()
				return m, nil
			}
			if row.isBool {
				newValue := "true"
				if row.value == "true" {
					newValue = "false"
				}
				return m, m.sendUpdatePolicySettingCmd(row.key, newValue)
			}
			m.policyEditingRow = m.policySelectedRow
			m.policyEditValue = ""
			if row.value != "(none)" {
				m.policyEditValue = row.value
			}
		}
	}

	return m, nil
}

func (m Model) handlePolicyASAModalKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.policyASAPending {
		return m, nil
	}

	switch m.policyASAMode {
	case policyASAModeNetworks:
		return m.handlePolicyASANetworkKeys(msg)
	case policyASAModeLimits:
		return m.handlePolicyASALimitsKeys(msg)
	case policyASAModeAddRef:
		return m.handlePolicyASAAddRefKeys(msg)
	case policyASAModeChoose:
		return m.handlePolicyASAChooseKeys(msg)
	case policyASAModeAddAmount:
		return m.handlePolicyASAAddAmountKeys(msg)
	case policyASAModeAlgoAmount:
		return m.handlePolicyASAAlgoAmountKeys(msg)
	default:
		m.policyASAMode = policyASAModeNetworks
		return m, nil
	}
}

func (m Model) handlePolicyASANetworkKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	count := len(m.policyASANetworks)
	switch msg.String() {
	case "esc", "q":
		m.discardPolicyASADrafts()
		m.viewState = ViewPolicyPanel
		return m, nil
	case "tab", "down", "j":
		if count > 0 {
			m.policyASAFocus = (m.policyASAFocus + 1) % count
		}
		return m, nil
	case "shift+tab", "up", "k":
		if count > 0 {
			m.policyASAFocus = (m.policyASAFocus + count - 1) % count
		}
		return m, nil
	case "enter":
		if count == 0 || m.policyASAFocus >= count {
			return m, nil
		}
		m.openPolicyASANetwork(m.policyASANetworks[m.policyASAFocus])
		return m, nil
	default:
		return m, nil
	}
}

func (m Model) handlePolicyASALimitsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	actions := 2
	algoRows := 1
	count := algoRows + len(m.policyASAEntries) + actions
	switch msg.String() {
	case "esc", "q":
		selectedNet := m.policyASASelectedNet
		m = m.startPolicyASAModal()
		m.policyASAMode = policyASAModeNetworks
		m.policyASAFocus = indexOfString(m.policyASANetworks, selectedNet)
		return m, nil
	case "tab", "down", "j":
		if count > 0 {
			m.policyASAFocus = (m.policyASAFocus + 1) % count
		}
		return m, nil
	case "shift+tab", "up", "k":
		if count > 0 {
			m.policyASAFocus = (m.policyASAFocus + count - 1) % count
		}
		return m, nil
	case "a":
		m.startPolicyASAAdd()
		return m, nil
	case "e":
		m.startPolicyAlgoEdit()
		return m, nil
	case "d":
		entryIndex := m.policyASAFocus - algoRows
		if entryIndex >= 0 && entryIndex < len(m.policyASAEntries) {
			m.policyASAEntries = append(m.policyASAEntries[:entryIndex], m.policyASAEntries[entryIndex+1:]...)
			m.syncPolicyASASelectedNetwork()
			m.policyASAFocus = m.policyASASaveFocus()
		}
		return m, nil
	case "s":
		return m.savePolicyASAAmounts()
	case "enter":
		switch m.policyASAFocus {
		case 0:
			m.startPolicyAlgoEdit()
			return m, nil
		case algoRows + len(m.policyASAEntries):
			m.startPolicyASAAdd()
			return m, nil
		case algoRows + len(m.policyASAEntries) + 1:
			return m.savePolicyASAAmounts()
		default:
			return m, nil
		}
	}
	return m, nil
}

func (m Model) handlePolicyASAAddRefKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.policyASAMode = policyASAModeLimits
		m.policyASAFocus = len(m.policyASAEntries)
		return m, nil
	case "backspace":
		if len(m.policyASAInput) > 0 {
			m.policyASAInput = m.policyASAInput[:len(m.policyASAInput)-1]
		}
		return m, nil
	case "enter":
		ref := strings.TrimSpace(m.policyASAInput)
		if ref == "" {
			m.lastError = "Enter an ASA ID or cached symbol"
			return m, nil
		}
		if assetID, err := strconv.ParseUint(ref, 10, 64); err == nil {
			return m, m.sendResolveASAMetadataCmd(m.policyASASelectedNet, assetID)
		}
		return m, m.sendSearchASAMetadataCmd(m.policyASASelectedNet, ref)
	default:
		if len(msg.String()) == 1 {
			m.policyASAInput += msg.String()
		}
		return m, nil
	}
}

func (m Model) handlePolicyASAChooseKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	count := len(m.policyASAMatches)
	switch msg.String() {
	case "esc":
		m.policyASAMode = policyASAModeAddRef
		m.policyASAFocus = 0
		return m, nil
	case "down", "j", "tab":
		if count > 0 {
			m.policyASAFocus = (m.policyASAFocus + 1) % count
		}
		return m, nil
	case "up", "k", "shift+tab":
		if count > 0 {
			m.policyASAFocus = (m.policyASAFocus + count - 1) % count
		}
		return m, nil
	case "enter":
		if count == 0 {
			return m, nil
		}
		selected := m.policyASAMatches[m.policyASAFocus]
		m.policyASASelectedAsset = &selected
		m.policyASAInput = strconv.FormatUint(selected.AssetID, 10)
		m.policyASAReviewInput = ""
		m.policyASADenyInput = ""
		m.policyASAAmountField = 0
		m.policyASAMode = policyASAModeAddAmount
		return m, nil
	}
	return m, nil
}

func (m Model) handlePolicyASAAddAmountKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.policyASAMode = policyASAModeAddRef
		return m, nil
	case "tab", "down", "up", "shift+tab":
		m.policyASAAmountField = 1 - m.policyASAAmountField
		return m, nil
	case "backspace":
		m.deletePolicyASAAmountRune()
		return m, nil
	case "enter":
		if m.policyASASelectedAsset == nil {
			m.lastError = "Resolve an ASA before entering transfer guards"
			m.policyASAMode = policyASAModeAddRef
			return m, nil
		}
		reviewAmount := strings.TrimSpace(m.policyASAReviewInput)
		maxAmount := strings.TrimSpace(m.policyASADenyInput)
		if err := validateDecimalAmount("ASA review threshold", reviewAmount, int(m.policyASASelectedAsset.Decimals)); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		if err := validateDecimalAmount("ASA deny threshold", maxAmount, int(m.policyASASelectedAsset.Decimals)); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		if reviewAmount == "" && maxAmount == "" {
			m.lastError = "Enter a review or deny threshold"
			return m, nil
		}
		m.upsertPolicyASAEntry(policyASAEntry{
			AssetID:      m.policyASASelectedAsset.AssetID,
			ReviewAmount: reviewAmount,
			MaxAmount:    maxAmount,
			Meta:         m.policyASASelectedAsset,
		})
		m.syncPolicyASASelectedNetwork()
		m.policyASAMode = policyASAModeLimits
		m.policyASAFocus = m.policyASASaveFocus()
		return m, nil
	default:
		if len(msg.String()) == 1 {
			m.appendPolicyASAAmountRune(msg.String())
		}
		return m, nil
	}
}

func (m Model) handlePolicyASAAlgoAmountKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.policyASAMode = policyASAModeLimits
		m.policyASAFocus = 0
		return m, nil
	case "tab", "down", "up", "shift+tab":
		m.policyASAAmountField = 1 - m.policyASAAmountField
		return m, nil
	case "backspace":
		m.deletePolicyASAAmountRune()
		return m, nil
	case "enter":
		reviewAmount := strings.TrimSpace(m.policyASAReviewInput)
		maxAmount := strings.TrimSpace(m.policyASADenyInput)
		if err := validateDecimalAmount("ALGO payment review threshold", reviewAmount, 6); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		if err := validateDecimalAmount("ALGO payment deny threshold", maxAmount, 6); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		if m.policyAlgoReviewValues == nil {
			m.policyAlgoReviewValues = make(map[string]string)
		}
		if m.policyAlgoValues == nil {
			m.policyAlgoValues = make(map[string]string)
		}
		m.policyAlgoReviewValues[m.policyASASelectedNet] = reviewAmount
		m.policyAlgoValues[m.policyASASelectedNet] = maxAmount
		m.policyASAMode = policyASAModeLimits
		m.policyASAFocus = m.policyASASaveFocus()
		return m, nil
	default:
		if len(msg.String()) == 1 {
			m.appendPolicyASAAmountRune(msg.String())
		}
		return m, nil
	}
}

func (m *Model) appendPolicyASAAmountRune(value string) {
	if m.policyASAAmountField == 0 {
		m.policyASAReviewInput += value
		return
	}
	m.policyASADenyInput += value
}

func (m *Model) deletePolicyASAAmountRune() {
	if m.policyASAAmountField == 0 {
		if len(m.policyASAReviewInput) > 0 {
			m.policyASAReviewInput = m.policyASAReviewInput[:len(m.policyASAReviewInput)-1]
		}
		return
	}
	if len(m.policyASADenyInput) > 0 {
		m.policyASADenyInput = m.policyASADenyInput[:len(m.policyASADenyInput)-1]
	}
}

func (m Model) policyASASaveFocus() int {
	return 1 + len(m.policyASAEntries) + 1
}

func (m *Model) applyPolicyASAAmountsSnapshot(amounts map[string]string) {
	copied := cloneStringMap(amounts)
	if m.policySettings == nil {
		m.policySettings = &PolicySettings{}
	}
	m.policySettings.MaxASAAmounts = copied
	m.policySettings.MaxASAAmountsMainnet = copied[apconfig.NetworkMainnet]
	m.policySettings.MaxASAAmountsTestnet = copied[apconfig.NetworkTestnet]
	m.policySettings.MaxASAAmountsBetanet = copied[apconfig.NetworkBetanet]
}

func (m *Model) applyPolicyASAReviewAmountsSnapshot(amounts map[string]string) {
	copied := cloneStringMap(amounts)
	if m.policySettings == nil {
		m.policySettings = &PolicySettings{}
	}
	m.policySettings.ReviewASAAmounts = copied
}

func (m *Model) applyPolicyAlgoPaymentsSnapshot(amounts map[string]string) {
	copied := cloneStringMap(amounts)
	if m.policySettings == nil {
		m.policySettings = &PolicySettings{}
	}
	m.policySettings.MaxAlgoPayments = copied
}

func (m *Model) applyPolicyAlgoReviewPaymentsSnapshot(amounts map[string]string) {
	copied := cloneStringMap(amounts)
	if m.policySettings == nil {
		m.policySettings = &PolicySettings{}
	}
	m.policySettings.ReviewAlgoPayments = copied
}

func (m Model) startPolicyASAModal() Model {
	maxAmounts := make(map[string]string)
	reviewAmounts := make(map[string]string)
	maxAlgoPayments := make(map[string]string)
	reviewAlgoPayments := make(map[string]string)
	metadata := make(map[string]map[uint64]ASAMetadataInfo)
	var networks []string
	if m.policySettings != nil {
		networks = append([]string(nil), m.policySettings.PolicyNetworks...)
		for network, value := range m.policySettings.ReviewAlgoPayments {
			reviewAlgoPayments[network] = value
		}
		for network, value := range m.policySettings.MaxAlgoPayments {
			maxAlgoPayments[network] = value
		}
		for network, value := range m.policySettings.ReviewASAAmounts {
			reviewAmounts[network] = value
		}
		for network, value := range m.policySettings.MaxASAAmounts {
			maxAmounts[network] = value
		}
		metadata = policyASAMetadataLookup(m.policySettings.PolicyASAMetadata)
		if m.policySettings.MaxASAAmountsMainnet != "" {
			maxAmounts[apconfig.NetworkMainnet] = m.policySettings.MaxASAAmountsMainnet
		}
		if m.policySettings.MaxASAAmountsTestnet != "" {
			maxAmounts[apconfig.NetworkTestnet] = m.policySettings.MaxASAAmountsTestnet
		}
		if m.policySettings.MaxASAAmountsBetanet != "" {
			maxAmounts[apconfig.NetworkBetanet] = m.policySettings.MaxASAAmountsBetanet
		}
	}
	if networks == nil {
		networks = mapKeys(maxAmounts)
		networks = append(networks, mapKeys(reviewAmounts)...)
		networks = append(networks, mapKeys(maxAlgoPayments)...)
		networks = append(networks, mapKeys(reviewAlgoPayments)...)
	}
	networks = sortedPolicyASANetworks(networks)
	filteredMaxAmounts := make(map[string]string, len(networks))
	filteredReviewAmounts := make(map[string]string, len(networks))
	filteredMaxAlgoPayments := make(map[string]string, len(networks))
	filteredReviewAlgoPayments := make(map[string]string, len(networks))
	for _, network := range networks {
		filteredMaxAmounts[network] = maxAmounts[network]
		filteredReviewAmounts[network] = reviewAmounts[network]
		filteredMaxAlgoPayments[network] = maxAlgoPayments[network]
		filteredReviewAlgoPayments[network] = reviewAlgoPayments[network]
	}

	m.policyASAFocus = 0
	m.policyASAValues = filteredMaxAmounts
	m.policyASAReviewValues = filteredReviewAmounts
	m.policyAlgoValues = filteredMaxAlgoPayments
	m.policyAlgoReviewValues = filteredReviewAlgoPayments
	m.policyASANetworks = networks
	m.policyASAMetadata = metadata
	m.policyASAPending = false
	m.policyASAPendingValues = nil
	m.policyASAReviewPendingValues = nil
	m.policyAlgoPendingValues = nil
	m.policyAlgoReviewPendingValues = nil
	m.policyASAMode = policyASAModeNetworks
	m.policyASASelectedNet = ""
	m.policyASAEntries = nil
	m.policyASAInput = ""
	m.policyASAReviewInput = ""
	m.policyASADenyInput = ""
	m.policyASAAmountField = 0
	m.policyASAMatches = nil
	m.policyASASelectedAsset = nil
	m.viewState = ViewPolicyASAModal
	return m
}

func (m *Model) discardPolicyASADrafts() {
	reset := (*m).startPolicyASAModal()
	reset.viewState = ViewPolicyPanel
	*m = reset
}

func (m *Model) openPolicyASANetwork(network string) {
	m.policyASASelectedNet = network
	m.policyASAEntries = parsePolicyASAEntries(m.policyASAReviewValues[network], m.policyASAValues[network], m.policyASAMetadata[network])
	m.policyASAFocus = 0
	m.policyASAMode = policyASAModeLimits
	m.policyASAInput = ""
	m.policyASAReviewInput = ""
	m.policyASADenyInput = ""
	m.policyASAAmountField = 0
	m.policyASAMatches = nil
	m.policyASASelectedAsset = nil
}

func (m *Model) startPolicyASAAdd() {
	m.policyASAMode = policyASAModeAddRef
	m.policyASAFocus = 0
	m.policyASAInput = ""
	m.policyASAReviewInput = ""
	m.policyASADenyInput = ""
	m.policyASAAmountField = 0
	m.policyASAMatches = nil
	m.policyASASelectedAsset = nil
}

func (m *Model) startPolicyAlgoEdit() {
	m.policyASAMode = policyASAModeAlgoAmount
	m.policyASAFocus = 0
	m.policyASAReviewInput = strings.TrimSpace(m.policyAlgoReviewValues[m.policyASASelectedNet])
	m.policyASADenyInput = strings.TrimSpace(m.policyAlgoValues[m.policyASASelectedNet])
	m.policyASAAmountField = 0
	m.policyASAInput = ""
	m.policyASAMatches = nil
	m.policyASASelectedAsset = nil
}

func (m *Model) syncPolicyASASelectedNetwork() {
	if m.policyASAValues == nil {
		m.policyASAValues = make(map[string]string)
	}
	if m.policyASAReviewValues == nil {
		m.policyASAReviewValues = make(map[string]string)
	}
	m.policyASAReviewValues[m.policyASASelectedNet] = formatPolicyASAEntries(m.policyASAEntries, policyASAReviewAmount)
	m.policyASAValues[m.policyASASelectedNet] = formatPolicyASAEntries(m.policyASAEntries, policyASAMaxAmount)
	m.syncPolicyASAMetadata()
}

func (m Model) savePolicyASAAmounts() (tea.Model, tea.Cmd) {
	m.syncPolicyASASelectedNetwork()
	maxAmounts := make(map[string]string, len(m.policyASANetworks))
	reviewAmounts := make(map[string]string, len(m.policyASANetworks))
	maxAlgoPayments := make(map[string]string, len(m.policyASANetworks))
	reviewAlgoPayments := make(map[string]string, len(m.policyASANetworks))
	for _, network := range m.policyASANetworks {
		reviewValue := strings.TrimSpace(m.policyASAReviewValues[network])
		if err := validatePolicyASAAmounts(reviewValue); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		maxValue := strings.TrimSpace(m.policyASAValues[network])
		if err := validatePolicyASAAmounts(maxValue); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		reviewAmounts[network] = reviewValue
		maxAmounts[network] = maxValue

		reviewAlgoValue := strings.TrimSpace(m.policyAlgoReviewValues[network])
		if err := validateDecimalAmount("ALGO payment review threshold", reviewAlgoValue, 6); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		maxAlgoValue := strings.TrimSpace(m.policyAlgoValues[network])
		if err := validateDecimalAmount("ALGO payment deny threshold", maxAlgoValue, 6); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		reviewAlgoPayments[network] = reviewAlgoValue
		maxAlgoPayments[network] = maxAlgoValue
	}
	m.policyASAPending = true
	m.policyASAPendingValues = cloneStringMap(maxAmounts)
	m.policyASAReviewPendingValues = cloneStringMap(reviewAmounts)
	m.policyAlgoPendingValues = cloneStringMap(maxAlgoPayments)
	m.policyAlgoReviewPendingValues = cloneStringMap(reviewAlgoPayments)
	return m, m.sendUpdatePolicyASAAmountsCmd(reviewAmounts, maxAmounts, reviewAlgoPayments, maxAlgoPayments)
}

func (m *Model) upsertPolicyASAEntry(entry policyASAEntry) {
	for i, existing := range m.policyASAEntries {
		if existing.AssetID == entry.AssetID {
			m.policyASAEntries[i] = entry
			return
		}
	}
	m.policyASAEntries = append(m.policyASAEntries, entry)
	sort.Slice(m.policyASAEntries, func(i, j int) bool {
		return m.policyASAEntries[i].AssetID < m.policyASAEntries[j].AssetID
	})
}

func (m *Model) syncPolicyASAMetadata() {
	if m.policyASAMetadata == nil {
		m.policyASAMetadata = make(map[string]map[uint64]ASAMetadataInfo)
	}
	if m.policyASAMetadata[m.policyASASelectedNet] == nil {
		m.policyASAMetadata[m.policyASASelectedNet] = make(map[uint64]ASAMetadataInfo)
	}
	for _, entry := range m.policyASAEntries {
		if entry.Meta != nil {
			m.policyASAMetadata[m.policyASASelectedNet][entry.AssetID] = *entry.Meta
		}
	}
}

func parsePolicyASAEntries(reviewRaw, maxRaw string, metadata map[uint64]ASAMetadataInfo) []policyASAEntry {
	entries := make(map[uint64]*policyASAEntry)
	for assetID, amount := range parsePolicyASAAmountEntries(reviewRaw) {
		entry := entries[assetID]
		if entry == nil {
			entry = &policyASAEntry{AssetID: assetID}
			entries[assetID] = entry
		}
		entry.ReviewAmount = amount
	}
	for assetID, amount := range parsePolicyASAAmountEntries(maxRaw) {
		entry := entries[assetID]
		if entry == nil {
			entry = &policyASAEntry{AssetID: assetID}
			entries[assetID] = entry
		}
		entry.MaxAmount = amount
	}
	out := make([]policyASAEntry, 0, len(entries))
	for assetID, entry := range entries {
		if meta, ok := metadata[assetID]; ok {
			entry.Meta = &meta
		}
		out = append(out, *entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AssetID < out[j].AssetID })
	return out
}

func parsePolicyASAAmountEntries(raw string) map[uint64]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make(map[uint64]string, len(parts))
	for _, part := range parts {
		fields := strings.Split(strings.TrimSpace(part), ":")
		if len(fields) != 2 {
			continue
		}
		assetID, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 64)
		if err != nil {
			continue
		}
		out[assetID] = strings.TrimSpace(fields[1])
	}
	return out
}

type policyASAAmountSelector func(policyASAEntry) string

func policyASAReviewAmount(entry policyASAEntry) string {
	return entry.ReviewAmount
}

func policyASAMaxAmount(entry policyASAEntry) string {
	return entry.MaxAmount
}

func formatPolicyASAEntries(entries []policyASAEntry, amountOf policyASAAmountSelector) string {
	if len(entries) == 0 {
		return ""
	}
	parts := make([]string, 0, len(entries))
	for _, entry := range entries {
		amount := strings.TrimSpace(amountOf(entry))
		if amount == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d:%s", entry.AssetID, amount))
	}
	return strings.Join(parts, ", ")
}

func indexOfString(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return 0
}

func policyASAMetadataLookup(in map[string][]ASAMetadataInfo) map[string]map[uint64]ASAMetadataInfo {
	out := make(map[string]map[uint64]ASAMetadataInfo, len(in))
	for network, items := range in {
		if out[network] == nil {
			out[network] = make(map[uint64]ASAMetadataInfo, len(items))
		}
		for _, item := range items {
			out[network][item.AssetID] = item
		}
	}
	return out
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func sortedPolicyASANetworks(networks []string) []string {
	seen := make(map[string]struct{}, len(networks))
	out := make([]string, 0, len(networks))
	for _, network := range networks {
		if _, ok := seen[network]; ok {
			continue
		}
		seen[network] = struct{}{}
		out = append(out, network)
	}
	sort.Strings(out)
	return out
}

func validatePolicySettingValue(key, value string) error {
	switch key {
	case adminproto.PolicySettingMaxFeeMicroAlgos:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		for _, r := range value {
			if r < '0' || r > '9' {
				return fmt.Errorf("%s must be an unsigned integer", key)
			}
		}
		return nil
	default:
		return nil
	}
}

func validateDecimalAmount(key, value string, maxDecimals int) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	dots := 0
	for _, r := range value {
		if r == '.' {
			dots++
			if dots > 1 {
				return fmt.Errorf("%s must be a non-negative decimal amount", key)
			}
			continue
		}
		if r < '0' || r > '9' {
			return fmt.Errorf("%s must be a non-negative decimal amount", key)
		}
	}
	if value == "." {
		return fmt.Errorf("%s must be a non-negative decimal amount", key)
	}
	if dot := strings.IndexByte(value, '.'); dot >= 0 && len(value)-dot-1 > maxDecimals {
		return fmt.Errorf("%s must have at most %d decimal places", key, maxDecimals)
	}
	return nil
}

func validatePolicyASAAmounts(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for _, part := range parts {
		pair := strings.Split(strings.TrimSpace(part), ":")
		if len(pair) != 2 || strings.TrimSpace(pair[0]) == "" || strings.TrimSpace(pair[1]) == "" {
			return fmt.Errorf("ASA guards must use asset_id:amount pairs")
		}
		for _, r := range strings.TrimSpace(pair[0]) {
			if r < '0' || r > '9' {
				return fmt.Errorf("ASA guards must use numeric asset IDs")
			}
		}
		amount := strings.TrimSpace(pair[1])
		dots := 0
		for _, r := range amount {
			if r == '.' {
				dots++
				if dots > 1 {
					return fmt.Errorf("ASA guards must use numeric amounts")
				}
				continue
			}
			if r < '0' || r > '9' {
				return fmt.Errorf("ASA guards must use numeric amounts")
			}
		}
		if amount == "." {
			return fmt.Errorf("ASA guards must use numeric amounts")
		}
	}
	return nil
}
