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
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policyexport"
	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// The policies view exports the node's active policy: every document, exactly
// as stored, and the node's policy context, into a new or empty directory, so
// the files can be checked, explained and edited offline with appolicy and
// installed again with apadmin policy apply. The documents are fetched one at
// a time against the snapshot the summary and context were read at, so the
// node refuses a fetch once either moved, and they are written only if
// together they are still the policy set the summary listed. A cosigner's
// export then reads the node's source token listing, a page at a time, and
// records which sources every selector has a token for; when the node will
// not say (a session without policy.update), the export records none and
// says so.

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
	// pendingID names the document or token listing request the export is
	// waiting for; responses to any other request are not the export's.
	pendingID string
	// listingTokens is set while the token listing is read into tokens.
	// tokenNote, when set, says why no token names were recorded.
	listingTokens bool
	tokens        apadminapp.SourceTokenNames
	tokenNote     string
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
	if !m.policySummaryReady() {
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
		return m.openFileBrowser(browsePolicyExportDir, export.path, name), nil
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
	if problem := m.policyContextProblem(); problem != "" {
		export.err = problem
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
	return m, m.sendGetPolicyDocumentCmd(key, snapshot, id)
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
		return m, nil
	}
	export.docs = append(export.docs, policyexport.Document{
		Key: doc.Key, Document: doc.Document, SHA256: export.expected[doc.Key],
	})
	if len(export.queue) > 0 {
		return m.fetchNextPolicyExportDocument()
	}
	if export.context.NodeRole == string(noderole.RoleCosigner) {
		export.tokens = apadminapp.SourceTokenNames{}
		return m.fetchPolicyExportSourceTokens("")
	}
	return m.writePolicyExport(nil)
}

// fetchPolicyExportSourceTokens asks for the page of the token listing that
// starts after after.
func (m Model) fetchPolicyExportSourceTokens(after string) (tea.Model, tea.Cmd) {
	export := &m.policies.export
	export.listingTokens = true
	export.busy = "Reading source token names..."
	export.pendingID = newRequestID("policy-export-tokens")
	id := export.pendingID
	return m, operationCmd(m.adminClient, id, func(c *IPCClient) error {
		return c.sendMessage(protocol.SourceTokenListMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenList, ID: id},
			After:       after,
		})
	})
}

// handlePolicyExportSourceTokens records one page of the token listing the
// export asked for, then asks for the next or writes the export. ok is
// false when msg answers some other request.
func (m Model) handlePolicyExportSourceTokens(msg sourceTokenListMsg) (tea.Model, tea.Cmd, bool) {
	export := &m.policies.export
	if !export.listingTokens || msg.ID == "" || msg.ID != export.pendingID {
		return m, nil, false
	}
	export.pendingID = ""
	after, done, err := export.tokens.Add(protocol.SourceTokenListResultMessage(msg))
	switch {
	case err != nil:
		next, cmd := m.writePolicyExportWithoutTokens(err)
		return next, cmd, true
	case done:
		next, cmd := m.writePolicyExport(export.tokens.Names())
		return next, cmd, true
	}
	next, cmd := m.fetchPolicyExportSourceTokens(after)
	return next, cmd, true
}

// writePolicyExportWithoutTokens writes the export with no token names, as
// when the node refused the listing, and keeps why for the result.
func (m Model) writePolicyExportWithoutTokens(err error) (tea.Model, tea.Cmd) {
	m.policies.export.tokenNote = "No source token names were recorded (" + err.Error() + "), so appolicy check gives no missing-token warning from this export."
	return m.writePolicyExport(nil)
}

// writePolicyExport writes the fetched documents with tokens, the token
// names to record (nil for none).
func (m Model) writePolicyExport(tokens map[string][]string) (tea.Model, tea.Cmd) {
	export := &m.policies.export
	export.listingTokens = false
	export.busy = "Writing policy files..."
	return m, writePolicyExportCmd(export.path, export.docs, export.context, tokens)
}

func writePolicyExportCmd(dir string, docs []policyexport.Document, context adminproto.PolicyContextView, tokens map[string][]string) tea.Cmd {
	return func() tea.Msg {
		paths, err := apadminapp.WritePolicyExport(dir, docs, context, tokens, time.Now())
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
	note := export.tokenNote
	m = m.closePolicyExport()
	m.policies.status = fmt.Sprintf("Exported %d policy document(s) to %s. Check them offline with: appolicy check %s", len(msg.Paths), msg.Dir, msg.Dir)
	if note != "" {
		m.policies.status += " " + note
	}
	return m, nil
}

// failPendingPolicyExport ends an export whose document request failed or
// could not be sent. A token listing that fails instead leaves the names
// unrecorded and writes the export. It reports false when id is not the
// export's request.
func (m Model) failPendingPolicyExport(id string, err error) (Model, tea.Cmd, bool) {
	export := &m.policies.export
	if id == "" || id != export.pendingID {
		return m, nil, false
	}
	export.pendingID = ""
	if export.listingTokens {
		next, cmd := m.writePolicyExportWithoutTokens(err)
		return next.(Model), cmd, true
	}
	export.busy = ""
	export.err = "Export failed: " + err.Error()
	return m, nil, true
}

func (m Model) renderPolicyExportForm() string {
	export := m.policies.export
	var body strings.Builder
	body.WriteString(titleStyle.Render("Export Policy"))
	body.WriteString("\n\n")
	body.WriteString("Export directory (new or empty):\n")
	body.WriteString(inputActiveStyle.Width(m.constrainParameterFieldWidth(60)).Render(terminalSafe(export.path)))
	body.WriteString("\n" + helpStyle.Render("ctrl+o browses"))
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
