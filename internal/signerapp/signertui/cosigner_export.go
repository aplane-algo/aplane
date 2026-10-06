// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/apadminapp"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/witness"
	tea "github.com/charmbracelet/bubbletea"
)

// The exported file is the cosigner key's public reference and nothing else.
// Clients configure the cosigner's address themselves, with endpoints add,
// so the file carries no endpoint, token, or host trust.

const cosignerKeyFileSuffix = ".aplane-cosigner.json"

func suggestedCosignerExportPath(witnessKeyID string) string {
	compact := strings.ToLower(strings.TrimSpace(witnessKeyID))
	if len(compact) > 10 {
		compact = compact[:10]
	}
	if compact == "" {
		compact = "public"
	}
	return "cosigner-" + compact + cosignerKeyFileSuffix
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
		if m.cosigner.exportFocus < m.cosignerExportButtonFocus() {
			m.cosigner.exportFocus++
			return m, nil
		}
		showJSON := m.cosigner.exportFocus == m.cosignerExportJSONButtonFocus()
		if !showJSON && strings.TrimSpace(m.cosigner.exportPath) == "" {
			m.cosigner.exportError = "Output path is required"
			return m, nil
		}
		m.cosigner.exportShowJSON = showJSON
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

func (m Model) cosignerExportButtonFocus() int     { return 1 }
func (m Model) cosignerExportJSONButtonFocus() int { return 2 }
func (m Model) cosignerExportLastFocus() int       { return m.cosignerExportJSONButtonFocus() }

func writeCosignerPublicEnvelopeCmd(path, envelopeJSON string) tea.Cmd {
	return func() tea.Msg {
		err := apadminapp.WriteCosignerPublicEnvelope(path, []byte(envelopeJSON))
		return CosignerExportWrittenMsg{Path: path, Error: err}
	}
}

// composeCosignerExportArtifact validates the daemon's public witness
// document and lays it out as the exported file.
func composeCosignerExportArtifact(witnessJSON string) (string, error) {
	reference, err := witness.ParsePublicReference([]byte(witnessJSON))
	if err != nil {
		return "", err
	}
	data, err := witness.MarshalPublicReference(reference)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// cosignerClientEndpointHint is what a client types after endpoints add: the
// configured advertise_url, or a placeholder when none is configured, plus
// --cosigner-port when an SSH endpoint's REST port is not the default, since
// that port is reached through the tunnel and the client cannot discover it.
func (m Model) cosignerClientEndpointHint() string {
	address := "ssh://<this cosigner's host>:<ssh port>"
	signerPort := 0
	if m.admin.settings != nil {
		if advertised := strings.TrimSpace(m.admin.settings.EndpointAdvertiseURL); advertised != "" {
			address = advertised
		}
		signerPort = m.admin.settings.SignerPort
	}
	if strings.HasPrefix(strings.ToLower(address), "ssh://") && signerPort != 0 && signerPort != apconfig.DefaultRESTPort {
		address += " --cosigner-port " + strconv.Itoa(signerPort)
	}
	return address
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
	body.WriteString(subtitleStyle.Render("Save this cosigner key's public key file on this machine. No private key, address, or access token is included."))
	body.WriteString("\n\nWitness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.cosigner.exportWitnessID), m.popupBodyWidth(90)))
	body.WriteString("\n\nOutput path:\n")
	pathStyle := inputInactiveStyle
	if m.cosigner.exportFocus == 0 {
		pathStyle = inputActiveStyle
	}
	body.WriteString(pathStyle.Width(m.constrainParameterFieldWidth(60)).Render(m.cosigner.exportPath))
	body.WriteString("\n" + helpStyle.Render("Public key only. Clients are given this cosigner's address separately."))
	body.WriteString("\n\n")
	button := buttonInactiveStyle.Render("EXPORT KEY FILE")
	if m.cosigner.exportFocus == m.cosignerExportButtonFocus() {
		button = buttonActiveStyle.Render("EXPORT KEY FILE")
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
	action := "Exporting Key File"
	if m.cosigner.exportShowJSON {
		action = "Loading Key JSON"
	}
	return m.renderPopup(60, titleStyle.Render(action)+"\n\n"+subtitleStyle.Render("Please wait...")+"\n")
}

func (m Model) renderCosignerExportResult() string {
	var body strings.Builder
	body.WriteString(titleStyle.Render("Cosigner Key Exported"))
	body.WriteString("\n\nPublic key file saved to:\n")
	body.WriteString(m.cosigner.exportWrittenPath)
	body.WriteString("\n\nWitness Key ID:\n")
	body.WriteString(wrapPlainText(groupedWitnessKeyID(m.cosigner.exportWitnessID), m.popupBodyWidth(90)))
	body.WriteString("\n")
	body.WriteString("\nOn the signer: Generate account -> Cosigner -> Use key file.")
	body.WriteString("\nOn each client: endpoints add " + m.cosignerClientEndpointHint())
	body.WriteString("\nA client connects to this cosigner once; later keys on it need no client change.\n")
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
