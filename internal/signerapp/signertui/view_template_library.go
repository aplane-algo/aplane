// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/aplane-algo/aplane/internal/keytypeux"
)

const libraryTypeCompiledProvider = "compiled_provider"

// The list columns are fixed so rows line up across scrolling. Together with
// the two-column cursor, single-space gaps, and the eight-column status, they
// reach column 78 of the MinWidth window.
const (
	libraryNameColumnWidth = 46
	libraryTypeColumnWidth = 20
)

func (m Model) renderTemplateLibrary() string {
	var sb strings.Builder

	sb.WriteString(titleStyle.Render("KeyType Library"))
	sb.WriteString("\n")

	if m.library.installStatus != "" {
		sb.WriteString(statusUnlockedStyle.Render(terminalSafe(m.library.installStatus)))
		sb.WriteString("\n\n")
	} else if m.library.installError != "" {
		sb.WriteString(errorStyle.Render(terminalSafe(m.library.installError)))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString(subtitleStyle.Render(m.templateLibrarySubtitle()))
		sb.WriteString("\n\n")
	}

	if len(m.library.templates) == 0 {
		sb.WriteString(subtitleStyle.Render("  No library entries found"))
		return sb.String()
	}

	selected := m.library.selectedTemplate
	if selected < 0 {
		selected = 0
	}
	if selected >= len(m.library.templates) {
		selected = len(m.library.templates) - 1
	}

	visible := m.templateLibraryVisibleHeight()
	start := scrollToSelection(m.library.scrollOffset, selected, len(m.library.templates), visible)
	sb.WriteString(scrollMoreAboveLine(start))
	sb.WriteString("\n")
	end := min(start+visible, len(m.library.templates))

	for i := start; i < end; i++ {
		tmpl := m.library.templates[i]
		prefix := "  "
		if i == selected {
			prefix = "> "
		}
		status := templateLibraryStatus(tmpl)
		line := fmt.Sprintf("%s%-*s %-*s %s", prefix,
			libraryNameColumnWidth, templateLibraryTitle(tmpl),
			libraryTypeColumnWidth, libraryTypeColumn(tmpl),
			status)
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

	sb.WriteString(scrollMoreBelowLine(len(m.library.templates) - end))
	sb.WriteString("\n")

	sb.WriteString("\n")
	sb.WriteString(m.renderTemplateDetails(m.library.templates[selected]))

	return sb.String()
}

// templateLibrarySubtitle points at the bounded presets, which are not library
// rows: a per-key type is always on, so a row could not offer to disable it.
// Cosigner nodes hold no bounded accounts.
func (m Model) templateLibrarySubtitle() string {
	if m.isCosignerNode() {
		return "Optional KeyTypes available for this identity"
	}
	return "Optional KeyTypes. Bounded presets are under Generate."
}

func (m Model) renderTemplateDetails(tmpl LibraryTemplateInfo) string {
	var sb strings.Builder

	if tmpl.Invalid != "" {
		sb.WriteString(errorStyle.Render("Invalid: " + terminalSafe(tmpl.Invalid)))
		sb.WriteString("\n")
		return sb.String()
	}
	if tmpl.Conflict != "" {
		sb.WriteString(errorStyle.Render("Conflict: " + terminalSafe(tmpl.Conflict)))
		sb.WriteString("\n")
		return sb.String()
	}

	if tmpl.DisplayName != "" {
		sb.WriteString(keyTypeStyle.Render(terminalSafe(tmpl.DisplayName)))
		sb.WriteString("\n")
	}
	if tmpl.Description != "" {
		sb.WriteString(subtitleStyle.Render(ellipsize(terminalSafe(tmpl.Description), m.templateLibraryRowWidth())))
		sb.WriteString("\n")
	}
	if publisher := keyTypePublisher(tmpl.KeyType); publisher != "" {
		sb.WriteString(fmt.Sprintf("Publisher: %s\n", publisher))
	}
	if tmpl.FileName != "" {
		sb.WriteString(fmt.Sprintf("File: %s\n", terminalSafe(tmpl.FileName)))
	} else if isCompiledProviderLibraryEntry(tmpl) {
		sb.WriteString("Source: built-in key type\n")
	}

	return sb.String()
}

// ellipsize cuts s to width columns, as the terminal draws them, ending the
// cut in "..." when width has room for more than that.
func ellipsize(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if width <= 3 {
		return ansi.Truncate(s, width, "")
	}
	return ansi.Truncate(s, width, "...")
}

// templateDetailsBoxLines lists a template's creation parameters and signing
// arguments, or nothing when it has neither.
func templateDetailsBoxLines(tmpl LibraryTemplateInfo) []string {
	var lines []string
	if len(tmpl.Parameters) > 0 {
		lines = append(lines, "Creation parameters:")
		for _, p := range tmpl.Parameters {
			lines = append(lines, templateFieldLines(p.Label, p.Name, p.Type, p.Required, p.Description)...)
		}
	}
	if len(tmpl.RuntimeArgs) > 0 {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "Signing arguments for generated keys:")
		for _, a := range tmpl.RuntimeArgs {
			lines = append(lines, templateFieldLines(a.Label, a.Name, a.Type, a.Required, a.Description)...)
		}
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
		sb.WriteString(fmt.Sprintf("Display name: %s\n", terminalSafe(tmpl.DisplayName)))
	}
	if tmpl.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", terminalSafe(tmpl.Description)))
	}
	body := templateDetailsBoxLines(tmpl)
	if len(body) == 0 {
		sb.WriteString("\nNo creation parameters or signing arguments.\n")
		return sb.String()
	}
	sb.WriteString("\n")
	sb.WriteString(strings.Join(body, "\n"))
	sb.WriteString("\n")
	return sb.String()
}

// templateFieldLines describes one creation parameter or signing argument:
// its label (its name when it has none), type and whether it is required,
// then its description.
func templateFieldLines(label, name, typ string, required bool, description string) []string {
	requirement := "optional"
	if required {
		requirement = "required"
	}
	if label == "" {
		label = name
	}
	lines := []string{terminalSafe(fmt.Sprintf("%s (%s, %s)", label, typ, requirement))}
	if description != "" {
		lines = append(lines, "  "+terminalSafe(description))
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
	tmpl := m.library.pendingTemplate
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
	sb.WriteString(templateDetailField("Source", libraryTypeColumn(*tmpl)))
	if tmpl.DisplayName != "" {
		sb.WriteString(templateDetailField("Name", terminalSafe(tmpl.DisplayName)))
	}
	if tmpl.Description != "" {
		sb.WriteString("\n")
		sb.WriteString(subtitleStyle.Render(wrapText(terminalSafe(tmpl.Description), 64)))
		sb.WriteString("\n")
	}
	if m.library.installError != "" {
		sb.WriteString("\n")
		sb.WriteString(errorStyle.Render(terminalSafe(m.library.installError)))
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(buttonPair(m.library.installFocus, "CANCEL", strings.ToUpper(libraryActionVerb(*tmpl)), nil))

	return m.renderPopup(72, sb.String())
}

func (m Model) renderTemplateInstalling() string {
	var sb strings.Builder
	sb.WriteString(titleStyle.Render(templateInstallingTitle(m.library.pendingTemplate)))
	sb.WriteString("\n\n")
	if m.library.pendingTemplate != nil {
		sb.WriteString(templateDetailField("Key Type", displayKeyType(m.library.pendingTemplate.KeyType)))
		if publisher := keyTypePublisher(m.library.pendingTemplate.KeyType); publisher != "" {
			sb.WriteString(templateDetailField("Publisher", publisher))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(subtitleStyle.Render("Please wait..."))
	sb.WriteString("\n")
	return m.renderPopup(50, sb.String())
}

// templateInstallingTitle says whether the pending entry is being enabled or
// disabled: the opposite of what it is now.
func templateInstallingTitle(pending *LibraryTemplateInfo) string {
	if pending == nil {
		return "Enabling Template Key Type"
	}
	verb, noun := "Enabling", "Template Key Type"
	if libraryEntryEnabled(*pending) {
		verb = "Disabling"
	}
	if isCompiledProviderLibraryEntry(*pending) {
		noun = "Key Type"
	}
	return verb + " " + noun
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
		return terminalSafe(tmpl.FileName)
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
	if libraryEntryEnabled(tmpl) {
		return "disable"
	}
	return "enable"
}

// The error prefixes a failed key type enable or disable shows.
const (
	libraryEnableFailure  = "Key type enable failed"
	libraryDisableFailure = "Key type disable failed"
)

func libraryEntryNoun(tmpl LibraryTemplateInfo) string {
	if isCompiledProviderLibraryEntry(tmpl) {
		return "key type"
	}
	return "template"
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
	default:
		return "dsa"
	}
}

func libraryConfirmTitle(tmpl LibraryTemplateInfo) string {
	if libraryEntryEnabled(tmpl) {
		return "Disable Key Type"
	}
	return "Enable Key Type"
}
