// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/version"
)

// adminRow represents a single row in the admin panel.
type adminRow struct {
	section  string   // Display section
	label    string   // Display label
	key      string   // Config key (empty = display-only)
	value    string   // Current display value
	editable bool     // Can be toggled/edited
	isBool   bool     // Toggle with enter vs text edit
	choices  []string // Cycle through these on enter (nil = text edit)
	action   string   // Non-empty = navigate/action row
}

// adminRows builds the list of admin panel rows from current settings.
func (m Model) adminRows() []adminRow {
	if m.adminSettings == nil {
		return nil
	}
	s := m.adminSettings
	isPromptMode := s.PassphraseMethod == "none" || s.PassphraseMethod == ""

	rows := []adminRow{
		{section: "User-Editable", label: "User Auto-Approve", key: adminproto.AdminSettingUserAutoApprove, value: boolStr(s.UserAutoApprove), editable: true, isBool: true},
		{section: "User-Editable", label: "Lock-on-disconnect", key: adminproto.AdminSettingLockOnDisconnect, value: boolStr(s.LockOnDisconnect), editable: isPromptMode, isBool: true},
		{section: "User-Editable", label: "Passphrase timeout", key: adminproto.AdminSettingPassphraseTimeout, value: s.PassphraseTimeout, editable: isPromptMode, isBool: false},
		{section: "User-Editable", label: "Color theme", key: adminproto.AdminSettingTheme, value: themeDisplay(s.Theme), editable: true, choices: []string{"auto", "dark", "light"}},
		{section: "Runtime", label: "Admin transport", key: "", value: m.transportLabel, editable: false},
		{section: "Runtime", label: "Node role", key: "", value: nodeRoleDisplay(s.NodeRole), editable: false},
		{section: "Runtime", label: "Passphrase unlock", key: "", value: passphraseMethodDisplay(s.PassphraseMethod), editable: false},
		{section: "Runtime", label: "Signer port", key: "", value: fmt.Sprintf("%d", s.SignerPort), editable: false},
		{section: "Runtime", label: "TEAL compile network", key: "", value: s.TEALCompileNet, editable: false},
		{section: "Runtime", label: "Policy", key: "", value: "view active policy", editable: false, action: "open_policy"},
	}

	if s.SSHEnabled {
		rows = append(rows,
			adminRow{section: "Runtime", label: "SSH port", key: "", value: fmt.Sprintf("%d", s.SSHPort), editable: false},
			adminRow{section: "Runtime", label: "SSH fingerprint", key: "", value: s.SSHFingerprint, editable: false},
			adminRow{section: "Runtime", label: "SSH clients connected", key: "", value: fmt.Sprintf("%d", s.SSHClients), editable: false},
		)
	} else {
		rows = append(rows,
			adminRow{section: "Runtime", label: "SSH", key: "", value: "disabled", editable: false},
		)
	}

	rows = append(rows,
		adminRow{section: "Runtime", label: "Build", key: "", value: version.Short(), editable: false},
	)

	return rows
}

// formatChoices renders choices like "< auto > dark   light" with the current value bracketed.
func formatChoices(current string, choices []string) string {
	var parts []string
	for _, c := range choices {
		if c == current {
			parts = append(parts, fmt.Sprintf("[ %s ]", c))
		} else {
			parts = append(parts, fmt.Sprintf("  %s  ", c))
		}
	}
	return strings.Join(parts, "")
}

// nextChoice returns the next value in the choices list, wrapping around.
func nextChoice(current string, choices []string) string {
	for i, c := range choices {
		if c == current {
			return choices[(i+1)%len(choices)]
		}
	}
	return choices[0]
}

func passphraseMethodDisplay(m string) string {
	switch m {
	case "none":
		return "prompt"
	case "passfile":
		return "passfile"
	case "systemd-creds":
		return "systemd"
	case "custom":
		return "custom"
	default:
		return m
	}
}

func nodeRoleDisplay(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return "signer"
	}
	return role
}

func themeDisplay(t string) string {
	if t == "" {
		return "auto"
	}
	return t
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// renderAdminPanel renders the admin control panel view.
func (m Model) renderAdminPanel() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("Settings"))
	sb.WriteString("\n\n")

	rows := m.adminRows()
	if len(rows) == 0 {
		sb.WriteString(subtitleStyle.Render("  Loading settings..."))
		sb.WriteString("\n")
	} else {
		// Find max label width for alignment
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
			if i == m.adminSelectedRow {
				prefix = "> "
			}

			// Format value display
			var valueStr string
			if m.adminEditingRow == i {
				valueStr = fmt.Sprintf("[%s_]", m.adminEditValue)
			} else if r.action != "" {
				valueStr = r.value
			} else if r.choices != nil {
				valueStr = formatChoices(r.value, r.choices)
			} else if r.isBool {
				if r.value == "true" {
					valueStr = "ON"
				} else {
					valueStr = "OFF"
				}
			} else {
				valueStr = r.value
			}

			line := fmt.Sprintf("%s%-*s  %s", prefix, maxLabel, r.label, valueStr)

			if i == m.adminSelectedRow {
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
