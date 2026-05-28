// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
)

type policyRow struct {
	section  string
	label    string
	key      string
	value    string
	editable bool
	isBool   bool
	action   string
}

func (m Model) policyRows() []policyRow {
	if m.policySettings == nil {
		return nil
	}
	s := m.policySettings
	return []policyRow{
		{section: "Auto-Rejection", label: "Reject foreign rekey", key: adminproto.PolicySettingRejectForeignRekey, value: boolStr(s.RejectForeignRekey), editable: true, isBool: true},
		{section: "Auto-Rejection", label: "Reject close remainder", key: adminproto.PolicySettingRejectCloseRemainder, value: boolStr(s.RejectCloseRemainder), editable: true, isBool: true},
		{section: "Auto-Rejection", label: "Reject asset close", key: adminproto.PolicySettingRejectAssetClose, value: boolStr(s.RejectAssetClose), editable: true, isBool: true},
		{section: "Auto-Rejection", label: "Reject clawback", key: adminproto.PolicySettingRejectClawback, value: boolStr(s.RejectClawback), editable: true, isBool: true},
		{section: "Auto-Rejection", label: "Max fee (microAlgos)", key: adminproto.PolicySettingMaxFeeMicroAlgos, value: emptyPolicyDisplay(s.MaxFeeMicroAlgos), editable: true},
		{section: "Transfer Guards", label: "Transfer guards", key: policyPanelActionTransferGuards, value: "edit per network", editable: true, action: "edit_transfer_guards"},
		{section: "Always Review", label: "Review warning txns", key: adminproto.PolicySettingAlwaysReviewWarnings, value: boolStr(s.AlwaysReviewWarnings), editable: true, isBool: true},
		{section: "Policy Auto-Approve", label: "Approve self no-op transfer", key: adminproto.PolicySettingAutoApproveSelfNoOpTransfer, value: boolStr(s.AutoApproveSelfNoOpTransfer), editable: true, isBool: true},
	}
}

func emptyPolicyDisplay(v string) string {
	if strings.TrimSpace(v) == "" {
		return "(none)"
	}
	return v
}

func (m Model) renderPolicyPanel() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Policy"))
	sb.WriteString("\n\n")

	rows := m.policyRows()
	if len(rows) == 0 {
		sb.WriteString(subtitleStyle.Render("  Loading policy..."))
		sb.WriteString("\n")
	} else {
		maxLabel := 0
		for _, r := range rows {
			if len(r.label) > maxLabel {
				maxLabel = len(r.label)
			}
		}

		section := ""
		for i, r := range rows {
			if r.section != section {
				if section != "" {
					sb.WriteString("\n")
				}
				section = r.section
				sb.WriteString(subtitleStyle.Render(section))
				sb.WriteString("\n")
			}

			prefix := "  "
			if i == m.policySelectedRow {
				prefix = "> "
			}

			valueStr := r.value
			if m.policyEditingRow == i {
				valueStr = fmt.Sprintf("[%s_]", m.policyEditValue)
			} else if r.isBool {
				if r.value == "true" {
					valueStr = "ON"
				} else {
					valueStr = "OFF"
				}
			}

			line := fmt.Sprintf("%s%-*s  %s", prefix, maxLabel, r.label, valueStr)
			if i == m.policySelectedRow {
				sb.WriteString(selectedStyle.Render(line))
			} else if r.isBool && r.value == "true" {
				sb.WriteString(statusUnlockedStyle.Render(line))
			} else {
				sb.WriteString(normalStyle.Render(line))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (m Model) renderPolicyASAModal() string {
	switch m.policyASAMode {
	case policyASAModeLimits:
		return m.renderPolicyASALimits()
	case policyASAModeAddRef:
		return m.renderPolicyASAAddRef()
	case policyASAModeChoose:
		return m.renderPolicyASAChoose()
	case policyASAModeAddAmount:
		return m.renderPolicyASAAddAmount()
	case policyASAModeAlgoAmount:
		return m.renderPolicyASAAlgoAmount()
	default:
		return m.renderPolicyASANetworks()
	}
}

func (m Model) renderPolicyASANetworks() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Transfer Guard Networks"))
	body.WriteString("\n\n")
	if m.policyASAPending {
		body.WriteString(statusUnlockedStyle.Render("Saving..."))
		body.WriteString("\n\n")
	} else {
		body.WriteString(helpStyle.Render("Changes are drafts until Save changes."))
		body.WriteString("\n\n")
	}

	if len(m.policyASANetworks) == 0 {
		body.WriteString(subtitleStyle.Render("No signer networks are configured for transfer policy."))
		body.WriteString("\n")
		body.WriteString(helpStyle.Render("Add algod networks to apsigner config.yaml."))
		body.WriteString("\n")
		return m.renderPopup(80, body.String())
	}

	for i, network := range m.policyASANetworks {
		prefix := "  "
		if i == m.policyASAFocus {
			prefix = "> "
		}

		count := len(parsePolicyASAEntries(m.policyASAReviewValues[network], m.policyASAValues[network], m.policyASAMetadata[network]))
		algoReviewText := emptyPolicyDisplay(m.policyAlgoReviewValues[network])
		algoMaxText := emptyPolicyDisplay(m.policyAlgoValues[network])
		countText := fmt.Sprintf("ALGO review %s / deny %s, no ASA guards", algoReviewText, algoMaxText)
		if count == 1 {
			countText = fmt.Sprintf("ALGO review %s / deny %s, 1 ASA guard", algoReviewText, algoMaxText)
		} else if count > 1 {
			countText = fmt.Sprintf("ALGO review %s / deny %s, %d ASA guards", algoReviewText, algoMaxText, count)
		}

		text := fmt.Sprintf("%s%-16s  %s", prefix, network, countText)
		if i == m.policyASAFocus {
			body.WriteString(selectedStyle.Render(text))
		} else {
			body.WriteString(normalStyle.Render(text))
		}
		body.WriteString("\n")
	}

	return m.renderPopup(80, body.String())
}

func (m Model) renderPolicyASALimits() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Transfer Guards: " + m.policyASASelectedNet))
	body.WriteString("\n\n")
	if m.policyASAPending {
		body.WriteString(statusUnlockedStyle.Render("Saving..."))
		body.WriteString("\n\n")
	} else {
		body.WriteString(helpStyle.Render("Changes are drafts until Save changes."))
		body.WriteString("\n\n")
	}

	algoPrefix := "  "
	if m.policyASAFocus == 0 {
		algoPrefix = "> "
	}
	header := fmt.Sprintf("%s%-12s  %-10s  %-14s  %-14s", "  ", "Asset ID", "Asset", "Review over", "Deny over")
	body.WriteString(subtitleStyle.Render(header))
	body.WriteString("\n")
	algoText := fmt.Sprintf(
		"%s%-12s  %-10s  %-14s  %-14s",
		algoPrefix,
		"",
		"ALGO",
		emptyPolicyDisplay(m.policyAlgoReviewValues[m.policyASASelectedNet]),
		emptyPolicyDisplay(m.policyAlgoValues[m.policyASASelectedNet]),
	)
	if m.policyASAFocus == 0 {
		body.WriteString(selectedStyle.Render(algoText))
	} else {
		body.WriteString(normalStyle.Render(algoText))
	}
	body.WriteString("\n")

	if len(m.policyASAEntries) == 0 {
		body.WriteString(subtitleStyle.Render("  No ASA guards configured"))
		body.WriteString("\n")
	} else {
		for i, entry := range m.policyASAEntries {
			focus := i + 1
			prefix := "  "
			if focus == m.policyASAFocus {
				prefix = "> "
			}
			text := fmt.Sprintf(
				"%s%-12d  %-10s  %-14s  %-14s",
				prefix,
				entry.AssetID,
				policyASAEntryLabel(entry),
				emptyPolicyDisplay(entry.ReviewAmount),
				emptyPolicyDisplay(entry.MaxAmount),
			)
			if focus == m.policyASAFocus {
				body.WriteString(selectedStyle.Render(text))
			} else {
				body.WriteString(normalStyle.Render(text))
			}
			body.WriteString("\n")
		}
	}

	actions := []string{"Add ASA guard", "Save changes"}
	for i, action := range actions {
		focus := 1 + len(m.policyASAEntries) + i
		prefix := "  "
		if focus == m.policyASAFocus {
			prefix = "> "
		}
		text := fmt.Sprintf("%s%s", prefix, action)
		if focus == m.policyASAFocus {
			body.WriteString(selectedStyle.Render(text))
		} else {
			body.WriteString(normalStyle.Render(text))
		}
		body.WriteString("\n")
	}

	return m.renderPopup(80, body.String())
}

func (m Model) renderPolicyASAAlgoAmount() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Edit ALGO Guard: " + m.policyASASelectedNet))
	body.WriteString("\n\n")
	body.WriteString(renderPolicyAmountInput("Review over", m.policyASAReviewInput, m.policyASAAmountField == 0))
	body.WriteString("\n")
	body.WriteString(renderPolicyAmountInput("Deny over", m.policyASADenyInput, m.policyASAAmountField == 1))
	body.WriteString("\n")
	body.WriteString(subtitleStyle.Render("Use ALGO display units; empty means no threshold."))
	return m.renderPopup(80, body.String())
}

func policyASAEntryLabel(entry policyASAEntry) string {
	if entry.Meta == nil {
		return ""
	}
	if unit := strings.TrimSpace(entry.Meta.UnitName); unit != "" {
		return unit
	}
	return strings.TrimSpace(entry.Meta.Name)
}

func (m Model) renderPolicyASAAddRef() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Add ASA Guard: " + m.policyASASelectedNet))
	body.WriteString("\n\n")
	body.WriteString(normalStyle.Render("Asset ID or cached symbol: "))
	body.WriteString(selectedStyle.Render(fmt.Sprintf("[%s_]", m.policyASAInput)))
	body.WriteString("\n")
	body.WriteString(subtitleStyle.Render("Numeric IDs may query algod; symbols only search signer cache."))
	return m.renderPopup(80, body.String())
}

func (m Model) renderPolicyASAChoose() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Choose ASA: " + m.policyASASelectedNet))
	body.WriteString("\n\n")
	for i, meta := range m.policyASAMatches {
		prefix := "  "
		if i == m.policyASAFocus {
			prefix = "> "
		}
		text := fmt.Sprintf("%s%-12d  %-10s  %-24s  %d decimals", prefix, meta.AssetID, meta.UnitName, meta.Name, meta.Decimals)
		if i == m.policyASAFocus {
			body.WriteString(selectedStyle.Render(text))
		} else {
			body.WriteString(normalStyle.Render(text))
		}
		body.WriteString("\n")
	}
	return m.renderPopup(80, body.String())
}

func (m Model) renderPolicyASAAddAmount() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Add ASA Guard: " + m.policyASASelectedNet))
	body.WriteString("\n\n")
	if m.policyASASelectedAsset != nil {
		meta := *m.policyASASelectedAsset
		body.WriteString(normalStyle.Render(fmt.Sprintf("ASA: %d", meta.AssetID)))
		if strings.TrimSpace(meta.UnitName) != "" {
			body.WriteString(normalStyle.Render(fmt.Sprintf(" (%s)", meta.UnitName)))
		}
		body.WriteString("\n")
		if strings.TrimSpace(meta.Name) != "" {
			body.WriteString(normalStyle.Render("Name: " + meta.Name))
			body.WriteString("\n")
		}
		body.WriteString(normalStyle.Render(fmt.Sprintf("Decimals: %d", meta.Decimals)))
		body.WriteString("\n\n")
	}
	body.WriteString(renderPolicyAmountInput("Review over", m.policyASAReviewInput, m.policyASAAmountField == 0))
	body.WriteString("\n")
	body.WriteString(renderPolicyAmountInput("Deny over", m.policyASADenyInput, m.policyASAAmountField == 1))
	body.WriteString("\n")
	body.WriteString(subtitleStyle.Render("Use display units."))
	return m.renderPopup(80, body.String())
}

func renderPolicyAmountInput(label, value string, focused bool) string {
	rendered := fmt.Sprintf("[%-12s]", value)
	if focused {
		rendered = fmt.Sprintf("[%s_]", value)
		return normalStyle.Render(fmt.Sprintf("%-12s ", label+":")) + selectedStyle.Render(rendered)
	}
	return normalStyle.Render(fmt.Sprintf("%-12s %s", label+":", rendered))
}
