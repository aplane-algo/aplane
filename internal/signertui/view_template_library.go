// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/aplane-algo/aplane/internal/keytypeux"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const libraryTypeCompiledProvider = "compiled_provider"

func (m Model) renderTemplateLibrary() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("KeyType Library"))
	sb.WriteString("\n")

	if m.templateInstallStatus != "" {
		sb.WriteString(statusUnlockedStyle.Render(m.templateInstallStatus))
		sb.WriteString("\n\n")
	} else if m.templateInstallError != "" {
		sb.WriteString(errorStyle.Render(m.templateInstallError))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString(subtitleStyle.Render("Optional KeyTypes available for this identity"))
		sb.WriteString("\n\n")
	}

	if len(m.libraryTemplates) == 0 {
		sb.WriteString(subtitleStyle.Render("  No library entries found"))
		return sb.String()
	}

	selected := m.selectedTemplate
	if selected < 0 {
		selected = 0
	}
	if selected >= len(m.libraryTemplates) {
		selected = len(m.libraryTemplates) - 1
	}

	visible := m.templateLibraryVisibleHeight()
	sb.WriteString(scrollMoreAboveLine(m.templateScrollOffset))
	sb.WriteString("\n")
	end := m.templateScrollOffset + visible
	if end > len(m.libraryTemplates) {
		end = len(m.libraryTemplates)
	}

	for i := m.templateScrollOffset; i < end; i++ {
		tmpl := m.libraryTemplates[i]
		prefix := "  "
		if i == selected {
			prefix = "> "
		}
		status := templateLibraryStatus(tmpl)
		line := fmt.Sprintf("%s%-34s %-8s %s", prefix, templateLibraryTitle(tmpl), libraryTypeColumn(tmpl), status)
		if i == selected {
			sb.WriteString(selectedStyle.Render(line))
		} else if tmpl.Invalid != "" || tmpl.Conflict != "" {
			sb.WriteString(errorStyle.Render(line))
		} else if libraryEntryEnabled(tmpl) {
			sb.WriteString(statusUnlockedStyle.Render(line))
		} else {
			sb.WriteString(normalStyle.Render(line))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(scrollMoreBelowLine(len(m.libraryTemplates) - end))
	sb.WriteString("\n")

	sb.WriteString("\n")
	sb.WriteString(m.renderTemplateDetails(m.libraryTemplates[selected]))

	return sb.String()
}

func (m Model) renderTemplateDetails(tmpl LibraryTemplateInfo) string {
	var sb strings.Builder

	if tmpl.Invalid != "" {
		sb.WriteString(errorStyle.Render("Invalid: " + tmpl.Invalid))
		sb.WriteString("\n")
		return sb.String()
	}
	if tmpl.Conflict != "" {
		sb.WriteString(errorStyle.Render("Conflict: " + tmpl.Conflict))
		sb.WriteString("\n")
		return sb.String()
	}

	if tmpl.DisplayName != "" {
		sb.WriteString(keyTypeStyle.Render(tmpl.DisplayName))
		sb.WriteString("\n")
	}
	if tmpl.Description != "" {
		sb.WriteString(subtitleStyle.Render(ellipsize(tmpl.Description, m.templateLibraryRowWidth())))
		sb.WriteString("\n")
	}
	if publisher := keyTypePublisher(tmpl.KeyType); publisher != "" {
		sb.WriteString(fmt.Sprintf("Publisher: %s\n", publisher))
	}
	if tmpl.FileName != "" {
		sb.WriteString(fmt.Sprintf("File: %s\n", tmpl.FileName))
	} else if isCompiledProviderLibraryEntry(tmpl) {
		sb.WriteString("Source: built-in key type\n")
	}

	return sb.String()
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

func templateDetailsBoxLines(tmpl LibraryTemplateInfo) []string {
	lines := make([]string, 0, (len(tmpl.Parameters)+len(tmpl.RuntimeArgs))*2+2)
	if len(tmpl.Parameters) > 0 {
		lines = append(lines, "Creation parameters:")
		lines = append(lines, templateParameterLines(tmpl.Parameters)...)
	}
	if len(tmpl.RuntimeArgs) > 0 {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "Signing arguments for generated keys:")
		lines = append(lines, templateSigningArgLines(tmpl.RuntimeArgs)...)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

// renderCompiledProviderDetailsText synthesizes the "v" body for a compiled
// provider, which has no on-disk YAML to fetch. The output mirrors the
// information a YAML library entry would carry in its header and parameter
// sections.
func renderCompiledProviderDetailsText(tmpl LibraryTemplateInfo) string {
	var sb strings.Builder
	sb.WriteString("Source: built-in key type\n")
	if publisher := keyTypePublisher(tmpl.KeyType); publisher != "" {
		sb.WriteString(fmt.Sprintf("Publisher: %s\n", publisher))
	}
	if tmpl.DisplayName != "" {
		sb.WriteString(fmt.Sprintf("Display name: %s\n", tmpl.DisplayName))
	}
	if tmpl.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", tmpl.Description))
	}
	body := templateDetailsBoxLines(tmpl)
	if len(body) == 1 && body[0] == "" {
		sb.WriteString("\nNo creation parameters or signing arguments.\n")
		return sb.String()
	}
	sb.WriteString("\n")
	sb.WriteString(strings.Join(body, "\n"))
	sb.WriteString("\n")
	return sb.String()
}

func templateParameterLines(params []protocol.TemplateParamInfo) []string {
	lines := make([]string, 0, len(params)*2)
	for _, p := range params {
		required := "optional"
		if p.Required {
			required = "required"
		}
		label := p.Label
		if label == "" {
			label = p.Name
		}
		lines = append(lines, fmt.Sprintf("%s (%s, %s)", label, p.Type, required))
		if p.Description != "" {
			lines = append(lines, "  "+p.Description)
		}
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func templateSigningArgLines(args []protocol.TemplateArgInfo) []string {
	lines := make([]string, 0, len(args)*2)
	for _, a := range args {
		required := "optional"
		if a.Required {
			required = "required"
		}
		label := a.Label
		if label == "" {
			label = a.Name
		}
		lines = append(lines, fmt.Sprintf("%s (%s, %s)", label, a.Type, required))
		if a.Description != "" {
			lines = append(lines, "  "+a.Description)
		}
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func (m Model) templateLibraryRowWidth() int {
	width := m.width - 8
	if width > 74 {
		width = 74
	}
	if width < 30 {
		width = 30
	}
	return width
}

func (m Model) renderTemplateInstallConfirm() string {
	var sb strings.Builder
	tmpl := m.pendingTemplate
	if tmpl == nil {
		sb.WriteString(errorStyle.Render("No library entry selected"))
		sb.WriteString("\n")
		return m.renderPopup(70, sb.String())
	}

	sb.WriteString(titleStyle.Render(libraryConfirmTitle(*tmpl)))
	sb.WriteString("\n\n")
	sb.WriteString(templateDetailField("Key type", displayKeyType(tmpl.KeyType)))
	if publisher := keyTypePublisher(tmpl.KeyType); publisher != "" {
		sb.WriteString(templateDetailField("Publisher", publisher))
	}
	sb.WriteString(templateDetailField("Source", libraryTypeLabel(*tmpl)))
	if tmpl.DisplayName != "" {
		sb.WriteString(templateDetailField("Name", tmpl.DisplayName))
	}
	if tmpl.Description != "" {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render(wrapText(tmpl.Description, 64)))
		sb.WriteString("\n")
	}
	if m.templateInstallError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(m.templateInstallError))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	cancel := buttonInactiveStyle.Render("CANCEL")
	confirm := buttonInactiveStyle.Render(strings.ToUpper(libraryActionVerb(*tmpl)))
	if m.templateInstallFocus == 0 {
		cancel = buttonActiveStyle.Render("CANCEL")
	} else {
		confirm = buttonActiveStyle.Render(strings.ToUpper(libraryActionVerb(*tmpl)))
	}
	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Center, cancel, "  ", confirm))

	return m.renderPopup(72, sb.String())
}

func (m Model) renderTemplateInstalling() string {
	var sb strings.Builder
	title := "Enabling Template Key Type"
	if m.pendingTemplate != nil {
		if isCompiledProviderLibraryEntry(*m.pendingTemplate) {
			if m.pendingTemplate.Installed {
				title = "Disabling Key Type"
			} else {
				title = "Enabling Key Type"
			}
		} else if m.pendingTemplate.Installed {
			if m.pendingTemplate.Enabled {
				title = "Disabling Template Key Type"
			} else {
				title = "Enabling Template Key Type"
			}
		}
	}
	sb.WriteString(titleStyle.Render(title))
	sb.WriteString("\n\n")
	if m.pendingTemplate != nil {
		sb.WriteString(templateDetailField("Key Type", displayKeyType(m.pendingTemplate.KeyType)))
		if publisher := keyTypePublisher(m.pendingTemplate.KeyType); publisher != "" {
			sb.WriteString(templateDetailField("Publisher", publisher))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")
	return m.renderPopup(50, sb.String())
}

func templateDetailField(label, value string) string {
	return fmt.Sprintf("%-10s %s\n", label+":", value)
}

func (m Model) templateLibraryVisibleHeight() int {
	h := m.height - 18
	if h < 4 {
		h = 4
	}
	if h > 12 {
		h = 12
	}
	return h
}

func templateLibraryTitle(tmpl LibraryTemplateInfo) string {
	if tmpl.KeyType != "" {
		return displayKeyType(tmpl.KeyType)
	}
	if tmpl.FileName != "" {
		return tmpl.FileName
	}
	return "(unknown)"
}

func templateLibraryStatus(tmpl LibraryTemplateInfo) string {
	return keytypeux.AvailabilityForCreation(libraryEntryEnabled(tmpl))
}

func isCompiledProviderLibraryEntry(tmpl LibraryTemplateInfo) bool {
	return tmpl.TemplateType == libraryTypeCompiledProvider
}

func libraryEntryEnabled(tmpl LibraryTemplateInfo) bool {
	if isCompiledProviderLibraryEntry(tmpl) {
		return tmpl.Installed
	}
	return tmpl.Installed && tmpl.Enabled
}

func libraryActionVerb(tmpl LibraryTemplateInfo) string {
	if isCompiledProviderLibraryEntry(tmpl) {
		if tmpl.Installed {
			return "deactivate"
		}
		return "activate"
	}
	if tmpl.Installed {
		if tmpl.Enabled {
			return "disable"
		}
		return "enable"
	}
	return "enable"
}

func libraryPastTense(_ LibraryTemplateInfo) string {
	return keytypeux.AvailableToCreate
}

func libraryDeactivatePastTense() string {
	return keytypeux.NotAvailableToCreate
}

func (m Model) libraryEntryForResult(keyType, fallbackTemplateType string) LibraryTemplateInfo {
	if m.pendingTemplate != nil && m.pendingTemplate.KeyType == keyType {
		return *m.pendingTemplate
	}
	for _, tmpl := range m.libraryTemplates {
		if tmpl.KeyType == keyType {
			return tmpl
		}
	}
	return LibraryTemplateInfo{KeyType: keyType, TemplateType: fallbackTemplateType}
}

func libraryActivateFailure(tmpl LibraryTemplateInfo) string {
	if isCompiledProviderLibraryEntry(tmpl) {
		return "Compiled provider activation failed"
	}
	return "Template key type enable failed"
}

func libraryDeactivateFailure(tmpl LibraryTemplateInfo) string {
	if isCompiledProviderLibraryEntry(tmpl) {
		return "Compiled provider deactivation failed"
	}
	return "Template key type disable failed"
}

func libraryEntryNoun(tmpl LibraryTemplateInfo) string {
	if isCompiledProviderLibraryEntry(tmpl) {
		return "key type"
	}
	return "template"
}

func libraryTypeLabel(tmpl LibraryTemplateInfo) string {
	if isCompiledProviderLibraryEntry(tmpl) {
		return compiledKeyTypeColumn(tmpl)
	}
	return tmpl.TemplateType
}

func libraryTypeColumn(tmpl LibraryTemplateInfo) string {
	if isCompiledProviderLibraryEntry(tmpl) {
		return compiledKeyTypeColumn(tmpl)
	}
	return tmpl.TemplateType
}

func compiledKeyTypeColumn(tmpl LibraryTemplateInfo) string {
	keyType := strings.ToLower(tmpl.KeyType)
	if dot := strings.Index(keyType, "."); dot >= 0 {
		keyType = keyType[dot+1:]
	}
	switch {
	case strings.HasPrefix(keyType, "falcon"):
		return "falcon"
	case strings.HasPrefix(keyType, "ecdsa"), strings.HasPrefix(keyType, "ecdsak1"):
		return "ecdsa"
	default:
		return "dsa"
	}
}

func libraryConfirmTitle(tmpl LibraryTemplateInfo) string {
	if isCompiledProviderLibraryEntry(tmpl) {
		if tmpl.Installed {
			return "Deactivate Compiled Provider"
		}
		return "Activate Compiled Provider"
	}
	if tmpl.Installed {
		if tmpl.Enabled {
			return "Disable Template Key Type"
		}
		return "Enable Template Key Type"
	}
	return "Enable Template Key Type"
}
