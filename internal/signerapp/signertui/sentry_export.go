// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

const sentryEnrollmentFileSuffix = ".aplane-sentry.json"

func suggestedSentryExportPath(witnessKeyID string) string {
	compact := strings.ToLower(strings.TrimSpace(witnessKeyID))
	if len(compact) > 10 {
		compact = compact[:10]
	}
	if compact == "" {
		compact = "public"
	}
	return "sentry-" + compact + sentryEnrollmentFileSuffix
}

func (m Model) openSentryExport() (tea.Model, tea.Cmd) {
	if !m.isSentryNode() || !witness.IsKeyType(m.details.keyType) {
		return m, nil
	}
	return m.openSentryExportFor(m.details.address, m.details.keyType, ViewKeyDetails)
}

func (m Model) openGeneratedSentryExport() (tea.Model, tea.Cmd) {
	if !m.isSentryNode() || !witness.IsKeyType(m.forms.generatedKeyType) {
		return m, nil
	}
	return m.openSentryExportFor(m.forms.generatedAddress, m.forms.generatedKeyType, ViewGenerateDisplay)
}

func (m Model) openSentryExportFor(rawWitnessKeyID, keyType string, returnView ViewState) (tea.Model, tea.Cmd) {
	if !m.isSentryNode() || !witness.IsKeyType(keyType) {
		return m, nil
	}
	witnessKeyID, err := witness.NormalizeID(rawWitnessKeyID)
	if err != nil {
		if returnView == ViewGenerateDisplay {
			m.forms.generateError = "Export unavailable: invalid Witness Key ID"
		} else {
			m.details.saveStatus = "Export unavailable: invalid Witness Key ID"
		}
		return m, nil
	}
	m.sentry.exportWitnessID = witnessKeyID
	m.sentry.exportPath = suggestedSentryExportPath(witnessKeyID)
	m.sentry.exportError = ""
	m.sentry.exportEndpoint = nil
	m.sentry.exportIncludeEndpoint = false
	m.sentry.exportEndpointError = ""
	if m.admin.settings != nil && strings.TrimSpace(m.admin.settings.EndpointAdvertiseURL) != "" {
		endpoint, endpointErr := apadminapp.BuildAdvertisedEndpointEnvelope(
			m.admin.settings.EndpointAdvertiseURL,
			m.admin.settings.SSHPort,
			m.admin.settings.SignerPort,
		)
		if endpointErr != nil {
			m.sentry.exportEndpointError = endpointErr.Error()
		} else {
			m.sentry.exportEndpoint = &endpoint
			m.sentry.exportIncludeEndpoint = true
		}
	}
	m.sentry.exportWrittenPath = ""
	m.sentry.exportShowJSON = false
	m.sentry.exportReturnView = returnView
	m.sentry.exportFocus = 0
	m.viewState = ViewSentryExportPath
	return m, nil
}

func (m Model) handleSentryExportPathKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.sentry.exportError = ""
		m.viewState = m.sentryExportReturnView()
		return m, nil
	case "tab", "down":
		m.sentry.exportFocus = (m.sentry.exportFocus + 1) % (m.sentryExportLastFocus() + 1)
		return m, nil
	case "shift+tab", "up":
		focusCount := m.sentryExportLastFocus() + 1
		m.sentry.exportFocus = (m.sentry.exportFocus + focusCount - 1) % focusCount
		return m, nil
	case "backspace":
		if m.sentry.exportFocus == 0 {
			m.sentry.exportPath = trimLastRune(m.sentry.exportPath)
		}
		m.sentry.exportError = ""
		return m, nil
	case "enter":
		if m.sentry.exportEndpoint != nil && m.sentry.exportFocus == 1 {
			m.sentry.exportIncludeEndpoint = !m.sentry.exportIncludeEndpoint
			return m, nil
		}
		fileFocus := m.sentryExportButtonFocus()
		if m.sentry.exportFocus < fileFocus {
			m.sentry.exportFocus++
			return m, nil
		}
		m.sentry.exportShowJSON = m.sentry.exportFocus == m.sentryExportJSONButtonFocus()
		if !m.sentry.exportShowJSON && strings.TrimSpace(m.sentry.exportPath) == "" {
			m.sentry.exportError = "Output path is required"
			return m, nil
		}
		if !m.sentry.exportShowJSON {
			m.sentry.exportPath = strings.TrimSpace(m.sentry.exportPath)
		}
		m.sentry.exportError = ""
		m.viewState = ViewSentryExporting
		return m, tea.Batch(
			m.sendExportSentryPublicCmd(m.sentry.exportWitnessID),
			m.waitForMessageCmd(),
		)
	}
	if msg.Type == tea.KeyRunes && m.sentry.exportFocus == 0 {
		m.sentry.exportPath += string(msg.Runes)
		m.sentry.exportError = ""
	}
	return m, nil
}

func (m Model) sentryExportButtonFocus() int {
	if m.sentry.exportEndpoint != nil {
		return 2
	}
	return 1
}

func (m Model) sentryExportJSONButtonFocus() int {
	return m.sentryExportButtonFocus() + 1
}

func (m Model) sentryExportLastFocus() int {
	return m.sentryExportJSONButtonFocus()
}

func writeSentryPublicEnvelopeCmd(path, envelopeJSON string) tea.Cmd {
	return func() tea.Msg {
		err := apadminapp.WriteSentryPublicEnvelope(path, []byte(envelopeJSON))
		return SentryExportWrittenMsg{Path: path, Error: err}
	}
}

func composeSentryExportArtifact(
	witnessJSON string,
	endpoint *endpointrefs.Envelope,
	includeEndpoint bool,
) (string, error) {
	if !includeEndpoint {
		endpoint = nil
	}
	reference, err := witness.ParsePublicReference([]byte(witnessJSON))
	if err != nil {
		return "", err
	}
	data, err := enrollment.Marshal(enrollment.Envelope{
		Schema: enrollment.Schema, Witness: reference, Endpoint: endpoint,
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (m Model) handleSentryExportResultKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc", "q", " ":
		m.sentry.exportError = ""
		m.viewState = m.sentryExportReturnView()
	}
	return m, nil
}

func (m Model) sentryExportReturnView() ViewState {
	if m.sentry.exportReturnView == ViewGenerateDisplay {
		return ViewGenerateDisplay
	}
	return ViewKeyDetails
}

func (m Model) renderSentryExportPath() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Export Sentry Key"))
	body.WriteString("\n\n")
	body.WriteString(subtitleStyle.Render("Save the public sentry key on this machine. No private key or access token is included."))
	body.WriteString("\n\nWitness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.sentry.exportWitnessID), m.popupBodyWidth(90)))
	body.WriteString("\n\nOutput path:\n")
	pathStyle := inputInactiveStyle
	if m.sentry.exportFocus == 0 {
		pathStyle = inputActiveStyle
	}
	body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(m.sentry.exportPath))
	if endpoint := m.sentry.exportEndpoint; endpoint != nil {
		body.WriteString("\n\n")
		checkbox := "[ ] Include advertised endpoint"
		if m.sentry.exportIncludeEndpoint {
			checkbox = "[x] Include advertised endpoint"
		}
		if m.sentry.exportFocus == 1 {
			body.WriteString(selectedStyle.Render(checkbox))
		} else {
			body.WriteString(checkbox)
		}
		body.WriteString("\n" + endpoint.URL)
		body.WriteString("\n" + helpStyle.Render("Public routing metadata only; no token or host trust."))
	} else if m.sentry.exportEndpointError != "" {
		body.WriteString("\n\n" + warningStyle.Render("Endpoint omitted: "+m.sentry.exportEndpointError))
	}
	body.WriteString("\n\n")
	button := buttonInactiveStyle.Render("EXPORT SENTRY KEY")
	if m.sentry.exportFocus == m.sentryExportButtonFocus() {
		button = buttonActiveStyle.Render("EXPORT SENTRY KEY")
	}
	body.WriteString(button)
	body.WriteString("\n\n")
	jsonButton := buttonInactiveStyle.Render("SHOW JSON")
	if m.sentry.exportFocus == m.sentryExportJSONButtonFocus() {
		jsonButton = buttonActiveStyle.Render("SHOW JSON")
	}
	body.WriteString(jsonButton)
	body.WriteString("\n")
	if m.sentry.exportError != "" {
		body.WriteString("\n" + errorStyle.Render(m.sentry.exportError) + "\n")
	}
	return m.renderPopup(90, body.String())
}

func (m Model) renderSentryExporting() string {
	action := "Exporting Sentry Key"
	if m.sentry.exportShowJSON {
		action = "Loading Sentry Key JSON"
	}
	return m.renderPopup(60, titleStyle.Render(action)+"\n\n"+subtitleStyle.Render("Please wait...")+"\n")
}

func (m Model) renderSentryExportResult() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Sentry Key Exported"))
	body.WriteString("\n\nPublic sentry key saved to:\n")
	body.WriteString(m.sentry.exportWrittenPath)
	body.WriteString("\n\nWitness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.sentry.exportWitnessID), m.popupBodyWidth(90)))
	if m.sentry.exportEndpoint != nil && m.sentry.exportIncludeEndpoint {
		body.WriteString("\n\nIncluded endpoint: " + m.sentry.exportEndpoint.URL)
	} else {
		body.WriteString("\n\nEndpoint: not included")
	}
	body.WriteString("\n")
	body.WriteString("\nNext: import this file in primary-signer apadmin, then use sentry add in apshell.\n")
	return m.renderPopup(90, body.String())
}

type sentryJSONTerminalClosedMsg struct{ err error }

// Release the TUI so terminal soft wrapping and scrollback preserve the original
// JSON lines. Rendering inside a pane would add borders or hard line breaks.
type sentryJSONTerminalDisplay struct {
	document string
	stdin    io.Reader
	stdout   io.Writer
}

func (d *sentryJSONTerminalDisplay) SetStdin(r io.Reader)  { d.stdin = r }
func (d *sentryJSONTerminalDisplay) SetStdout(w io.Writer) { d.stdout = w }
func (d *sentryJSONTerminalDisplay) SetStderr(io.Writer)   {}

func (d *sentryJSONTerminalDisplay) Run() error {
	if _, err := io.WriteString(d.stdout, "\nSentry key JSON — select the document below to copy:\n\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(d.stdout, d.document); err != nil {
		return err
	}
	if _, err := io.WriteString(d.stdout, "\n\nPress Enter to return to the export screen.\n"); err != nil {
		return err
	}
	_, err := bufio.NewReader(d.stdin).ReadString('\n')
	return err
}
