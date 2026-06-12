// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policytui

// Home screen: top-level policy field list and summaries.

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

const policyFieldLabelWidth = 36

const policyFieldValueWidth = 34

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

func blockedDestinationsSummary(c *policy.StoredConfig) string {
	if c == nil || c.TransferPolicy == nil || len(c.TransferPolicy.BlockedDestinations) == 0 {
		return "-"
	}
	if len(c.TransferPolicy.BlockedDestinations) == 1 {
		return c.TransferPolicy.BlockedDestinations[0]
	}
	return fmt.Sprintf("%d destinations", len(c.TransferPolicy.BlockedDestinations))
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
