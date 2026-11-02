// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/policyexport"
	tea "github.com/charmbracelet/bubbletea"
)

// The policies view exports the node's active policy: every document, exactly
// as stored, and the node's policy context, into a new or empty directory, so
// the files can be checked, explained and edited offline with appolicy and
// installed again with apadmin policy apply. The documents are fetched one at
// a time against the snapshot the summary and context were read at, so the
// node refuses a fetch once either moved, and they are written only if
// together they are still the policy set the summary listed.

// policyExportState is the export directory prompt and the fetch in progress.
type policyExportState struct {
	path string
	// busy is shown while documents are fetched or written; keys other than
	// esc are ignored until it clears.
	busy string
	err  string

	// queue holds the keys still to fetch, docs the documents fetched so far.
	queue    []string
	docs     []policyexport.Document
	expected map[string]string
	// context is the node's context the export writes, and snapshot the
	// composite snapshot every document is fetched against.
	context  adminproto.PolicyContextView
	snapshot string
	// pendingID names the document request the export is waiting for;
	// responses to any other request are not the export's.
	pendingID string
}

// PolicyExportWrittenMsg reports the end of an export's write.
type PolicyExportWrittenMsg struct {
	Dir   string
	Paths []string
	Err   error
}

// suggestedPolicyExportDir names a new directory in the home directory.
func suggestedPolicyExportDir(now time.Time) string {
	return "~/policy-export-" + now.UTC().Format("20060102-150405")
}

func (m Model) openPolicyExport() (tea.Model, tea.Cmd) {
	if m.policies.loading || m.policies.err != "" || !m.policies.policy.Success {
		return m, nil
	}
	m.policies.export = policyExportState{path: suggestedPolicyExportDir(time.Now())}
	m.policies.status = ""
	m.viewState = ViewPolicyExportForm
	return m, nil
}

func (m Model) closePolicyExport() Model {
	m.policies.export = policyExportState{}
	m.viewState = ViewPolicies
	return m
}

func (m Model) handlePolicyExportFormKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		return m.closePolicyExport(), nil
	}
	export := &m.policies.export
	if export.busy != "" {
		return m, nil
	}
	switch msg.String() {
	case "enter":
		return m.startPolicyExport()
	case fileBrowserKey:
		name := filepath.Base(suggestedPolicyExportDir(time.Now()))
		return m.openFileBrowser(browsePolicyExportDir, export.path, "", name), nil
	case "backspace", "delete":
		export.path = trimLastRune(export.path)
		export.err = ""
		return m, nil
	}
	if msg.Type == tea.KeyRunes {
		export.path += string(msg.Runes)
		export.err = ""
	}
	return m, nil
}

// expandHomePath resolves a leading ~ to the user's home directory.
func expandHomePath(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/")), nil
}

// startPolicyExport fetches the first document the summary lists.
func (m Model) startPolicyExport() (tea.Model, tea.Cmd) {
	export := &m.policies.export
	path := strings.TrimSpace(export.path)
	if path == "" {
		export.err = "An export directory is required"
		return m, nil
	}
	dir, err := expandHomePath(path)
	if err != nil {
		export.err = err.Error()
		return m, nil
	}
	export.path = dir
	summary := m.policies.policy
	export.queue = nil
	export.docs = nil
	export.expected = make(map[string]string, len(summary.Documents))
	for _, doc := range summary.Documents {
		export.queue = append(export.queue, doc.Key)
		export.expected[doc.Key] = doc.SHA256
	}
	if m.policies.snapshot == "" || m.policies.loadedContext == nil {
		export.err = "The node's policy context is still loading; try again"
		return m, nil
	}
	export.context = apadminapp.PolicyContextViewFromMessage(*m.policies.loadedContext)
	export.snapshot = m.policies.snapshot
	if len(export.queue) == 0 {
		export.err = "The node lists no policy documents to export"
		return m, nil
	}
	return m.fetchNextPolicyExportDocument()
}

func (m Model) fetchNextPolicyExportDocument() (tea.Model, tea.Cmd) {
	export := &m.policies.export
	key := export.queue[0]
	export.queue = export.queue[1:]
	total := len(export.expected)
	export.busy = fmt.Sprintf("Reading policy documents (%d of %d)...", total-len(export.queue), total)
	export.pendingID = newRequestID("policy-export-doc")
	id, snapshot := export.pendingID, export.snapshot
	return m, tea.Batch(
		policyRequestCmd(m.adminClient, id, func(c *IPCClient) error { return c.SendGetPolicyDocumentAt(key, snapshot, id) }),
		m.waitForMessageCmd(),
	)
}

// handlePolicyExportDocumentLoaded records one fetched document, then fetches
// the next or writes them all.
func (m Model) handlePolicyExportDocumentLoaded(msg PolicyDocumentLoadedMsg) (tea.Model, tea.Cmd) {
	export := &m.policies.export
	export.pendingID = ""
	doc := msg.Document
	if !doc.Success {
		export.busy = ""
		export.err = policyResultError(doc.Code, doc.Error, "a policy document is unavailable")
		return m, m.waitForMessageCmd()
	}
	export.docs = append(export.docs, policyexport.Document{Key: doc.Key, Document: doc.Document, SHA256: export.expected[doc.Key]})
	if len(export.queue) > 0 {
		return m.fetchNextPolicyExportDocument()
	}
	export.busy = "Writing policy files..."
	return m, tea.Batch(writePolicyExportCmd(export.path, export.docs, export.context), m.waitForMessageCmd())
}

func writePolicyExportCmd(dir string, docs []policyexport.Document, context adminproto.PolicyContextView) tea.Cmd {
	return func() tea.Msg {
		paths, err := apadminapp.WritePolicyExport(dir, docs, context, time.Now())
		return PolicyExportWrittenMsg{Dir: dir, Paths: paths, Err: err}
	}
}

func (m Model) handlePolicyExportWritten(msg PolicyExportWrittenMsg) (tea.Model, tea.Cmd) {
	if m.viewState != ViewPolicyExportForm || msg.Dir != m.policies.export.path {
		return m, nil
	}
	export := &m.policies.export
	export.busy = ""
	if msg.Err != nil {
		export.err = msg.Err.Error()
		return m, nil
	}
	m = m.closePolicyExport()
	m.policies.status = fmt.Sprintf("Exported %d policy document(s) to %s. Check them offline with: appolicy check %s", len(msg.Paths), msg.Dir, msg.Dir)
	return m, nil
}

// failPendingPolicyExport ends an export whose document request could not be
// sent. It reports false when id is not the export's request.
func (m Model) failPendingPolicyExport(id string, err error) (Model, bool) {
	export := &m.policies.export
	if id == "" || id != export.pendingID {
		return m, false
	}
	export.pendingID = ""
	export.busy = ""
	export.err = "Export failed: " + err.Error()
	return m, true
}

func (m Model) renderPolicyExportForm() string {
	export := m.policies.export
	var body strings.Builder
	body.WriteString(titleStyle.Render("Export Policy"))
	body.WriteString("\n\n")
	body.WriteString(subtitleStyle.Render("Writes every active policy document, exactly as stored, as default.json and <key>.json, with the node's context in .appolicy/node.json."))
	body.WriteString("\n\n")
	body.WriteString("Export directory (new or empty):\n")
	body.WriteString(inputActiveStyle.Width(m.constrainParameterFieldWidth(60)).Render(terminalSafe(export.path)))
	body.WriteString("\n" + helpStyle.Render("ctrl+o browses for where to create it. Check, explain or edit the files offline with appolicy; install changes with apadmin policy apply."))
	body.WriteString("\n")
	if export.busy != "" {
		body.WriteString("\n")
		body.WriteString(subtitleStyle.Render(export.busy))
		body.WriteString("\n")
	}
	if export.err != "" {
		body.WriteString("\n")
		body.WriteString(errorStyle.Render(wrapPlainText(terminalSafeLines(export.err), m.popupBodyWidth(90))))
		body.WriteString("\n")
	}
	return m.renderPopup(90, body.String())
}
