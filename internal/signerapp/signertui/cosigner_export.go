// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/cosigner/enrollment"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

const cosignerEnrollmentFileSuffix = ".aplane-cosigner.json"

func suggestedCosignerExportPath(witnessKeyID string) string {
	compact := strings.ToLower(strings.TrimSpace(witnessKeyID))
	if len(compact) > 10 {
		compact = compact[:10]
	}
	if compact == "" {
		compact = "public"
	}
	return "cosigner-" + compact + cosignerEnrollmentFileSuffix
}

func (m Model) openCosignerExport() (tea.Model, tea.Cmd) {
	if !m.isCosignerNode() || !witness.IsKeyType(m.details.keyType) {
		return m, nil
	}
	return m.openCosignerExportFor(m.details.address, m.details.keyType, ViewKeyDetails)
}

func (m Model) openGeneratedCosignerExport() (tea.Model, tea.Cmd) {
	if !m.isCosignerNode() || !witness.IsKeyType(m.forms.generatedKeyType) {
		return m, nil
	}
	return m.openCosignerExportFor(m.forms.generatedAddress, m.forms.generatedKeyType, ViewGenerateDisplay)
}

func (m Model) openCosignerExportFor(rawWitnessKeyID, keyType string, returnView ViewState) (tea.Model, tea.Cmd) {
	if !m.isCosignerNode() || !witness.IsKeyType(keyType) {
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
	m.cosigner.exportWitnessID = witnessKeyID
	m.cosigner.exportPath = suggestedCosignerExportPath(witnessKeyID)
	m.cosigner.exportError = ""
	m.cosigner.exportEndpoint = nil
	m.cosigner.exportIncludeEndpoint = false
	m.cosigner.exportEndpointError = ""
	if m.admin.settings != nil && strings.TrimSpace(m.admin.settings.EndpointAdvertiseURL) != "" {
		endpoint, endpointErr := apadminapp.BuildAdvertisedEndpointEnvelope(
			m.admin.settings.EndpointAdvertiseURL,
			m.admin.settings.SSHPort,
			m.admin.settings.SignerPort,
		)
		if endpointErr != nil {
			m.cosigner.exportEndpointError = endpointErr.Error()
		} else {
			m.cosigner.exportEndpoint = &endpoint
			m.cosigner.exportIncludeEndpoint = true
		}
	}
	m.cosigner.exportWrittenPath = ""
	m.cosigner.exportShowJSON = false
	m.cosigner.exportReturnView = returnView
	m.cosigner.exportFocus = 0
	m.viewState = ViewCosignerExportPath
	return m, nil
}

func (m Model) handleCosignerExportPathKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.cosigner.exportError = ""
		m.viewState = m.cosignerExportReturnView()
		return m, nil
	case "tab", "down":
		m.cosigner.exportFocus = (m.cosigner.exportFocus + 1) % (m.cosignerExportLastFocus() + 1)
		return m, nil
	case "shift+tab", "up":
		focusCount := m.cosignerExportLastFocus() + 1
		m.cosigner.exportFocus = (m.cosigner.exportFocus + focusCount - 1) % focusCount
		return m, nil
	case "backspace":
		if m.cosigner.exportFocus == 0 {
			m.cosigner.exportPath = trimLastRune(m.cosigner.exportPath)
		}
		m.cosigner.exportError = ""
		return m, nil
	case "enter":
		if m.cosigner.exportEndpoint != nil && m.cosigner.exportFocus == 1 {
			m.cosigner.exportIncludeEndpoint = !m.cosigner.exportIncludeEndpoint
			return m, nil
		}
		fileFocus := m.cosignerExportButtonFocus()
		if m.cosigner.exportFocus < fileFocus {
			m.cosigner.exportFocus++
			return m, nil
		}
		m.cosigner.exportShowJSON = m.cosigner.exportFocus == m.cosignerExportJSONButtonFocus()
		if !m.cosigner.exportShowJSON && strings.TrimSpace(m.cosigner.exportPath) == "" {
			m.cosigner.exportError = "Output path is required"
			return m, nil
		}
		if !m.cosigner.exportShowJSON {
			m.cosigner.exportPath = strings.TrimSpace(m.cosigner.exportPath)
		}
		m.cosigner.exportError = ""
		m.viewState = ViewCosignerExporting
		return m, tea.Batch(
			m.sendExportCosignerPublicCmd(m.cosigner.exportWitnessID),
			m.waitForMessageCmd(),
		)
	}
	if msg.Type == tea.KeyRunes && m.cosigner.exportFocus == 0 {
		m.cosigner.exportPath += string(msg.Runes)
		m.cosigner.exportError = ""
	}
	return m, nil
}

func (m Model) cosignerExportButtonFocus() int {
	if m.cosigner.exportEndpoint != nil {
		return 2
	}
	return 1
}

func (m Model) cosignerExportJSONButtonFocus() int {
	return m.cosignerExportButtonFocus() + 1
}

func (m Model) cosignerExportLastFocus() int {
	return m.cosignerExportJSONButtonFocus()
}

func writeCosignerPublicEnvelopeCmd(path, envelopeJSON string) tea.Cmd {
	return func() tea.Msg {
		err := apadminapp.WriteCosignerPublicEnvelope(path, []byte(envelopeJSON))
		return CosignerExportWrittenMsg{Path: path, Error: err}
	}
}

func composeCosignerExportArtifact(
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

func (m Model) handleCosignerExportResultKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc", "q", " ":
		m.cosigner.exportError = ""
		m.viewState = m.cosignerExportReturnView()
	}
	return m, nil
}

func (m Model) cosignerExportReturnView() ViewState {
	if m.cosigner.exportReturnView == ViewGenerateDisplay {
		return ViewGenerateDisplay
	}
	return ViewKeyDetails
}

func (m Model) renderCosignerExportPath() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Export Cosigner Key"))
	body.WriteString("\n\n")
	body.WriteString(subtitleStyle.Render("Save the public cosigner key on this machine. No private key or access token is included."))
	body.WriteString("\n\nWitness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.cosigner.exportWitnessID), m.popupBodyWidth(90)))
	body.WriteString("\n\nOutput path:\n")
	pathStyle := inputInactiveStyle
	if m.cosigner.exportFocus == 0 {
		pathStyle = inputActiveStyle
	}
	body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(m.cosigner.exportPath))
	if endpoint := m.cosigner.exportEndpoint; endpoint != nil {
		body.WriteString("\n\n")
		checkbox := "[ ] Include advertised endpoint"
		if m.cosigner.exportIncludeEndpoint {
			checkbox = "[x] Include advertised endpoint"
		}
		if m.cosigner.exportFocus == 1 {
			body.WriteString(selectedStyle.Render(checkbox))
		} else {
			body.WriteString(checkbox)
		}
		body.WriteString("\n" + endpoint.URL)
		body.WriteString("\n" + helpStyle.Render("Public routing metadata only; no token or host trust."))
	} else if m.cosigner.exportEndpointError != "" {
		body.WriteString("\n\n" + warningStyle.Render("Endpoint omitted: "+m.cosigner.exportEndpointError))
	}
	body.WriteString("\n\n")
	button := buttonInactiveStyle.Render("EXPORT COSIGNER KEY")
	if m.cosigner.exportFocus == m.cosignerExportButtonFocus() {
		button = buttonActiveStyle.Render("EXPORT COSIGNER KEY")
	}
	body.WriteString(button)
	body.WriteString("\n\n")
	jsonButton := buttonInactiveStyle.Render("SHOW JSON")
	if m.cosigner.exportFocus == m.cosignerExportJSONButtonFocus() {
		jsonButton = buttonActiveStyle.Render("SHOW JSON")
	}
	body.WriteString(jsonButton)
	body.WriteString("\n")
	if m.cosigner.exportError != "" {
		body.WriteString("\n" + errorStyle.Render(m.cosigner.exportError) + "\n")
	}
	return m.renderPopup(90, body.String())
}

func (m Model) renderCosignerExporting() string {
	action := "Exporting Cosigner Key"
	if m.cosigner.exportShowJSON {
		action = "Loading Cosigner Key JSON"
	}
	return m.renderPopup(60, titleStyle.Render(action)+"\n\n"+subtitleStyle.Render("Please wait...")+"\n")
}

func (m Model) renderCosignerExportResult() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Cosigner Key Exported"))
	body.WriteString("\n\nPublic cosigner key saved to:\n")
	body.WriteString(m.cosigner.exportWrittenPath)
	body.WriteString("\n\nWitness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.cosigner.exportWitnessID), m.popupBodyWidth(90)))
	if m.cosigner.exportEndpoint != nil && m.cosigner.exportIncludeEndpoint {
		body.WriteString("\n\nIncluded endpoint: " + m.cosigner.exportEndpoint.URL)
	} else {
		body.WriteString("\n\nEndpoint: not included")
	}
	body.WriteString("\n")
	body.WriteString("\nNext: import this file in primary-signer apadmin, then use cosigner add in apshell.\n")
	return m.renderPopup(90, body.String())
}

type cosignerJSONTerminalClosedMsg struct{ err error }

// Release the TUI so terminal soft wrapping and scrollback preserve the original
// JSON lines. Rendering inside a pane would add borders or hard line breaks.
type cosignerJSONTerminalDisplay struct {
	document string
	stdin    io.Reader
	stdout   io.Writer
}

func (d *cosignerJSONTerminalDisplay) SetStdin(r io.Reader)  { d.stdin = r }
func (d *cosignerJSONTerminalDisplay) SetStdout(w io.Writer) { d.stdout = w }
func (d *cosignerJSONTerminalDisplay) SetStderr(io.Writer)   {}

func (d *cosignerJSONTerminalDisplay) Run() error {
	if _, err := io.WriteString(d.stdout, "\nCosigner key JSON — select the document below to copy:\n\n"); err != nil {
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
