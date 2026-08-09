// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
	"github.com/aplane-algo/aplane/internal/signerapp/policytui"
	tea "github.com/charmbracelet/bubbletea"
)

const policyEditorRequestTimeout = 10 * time.Second

type policyEditorLoadedMsg struct {
	target policyeditor.Target
	store  *policyeditor.AdminStore
	stored *policy.StoredConfig
	err    error
}

type policyEditorClosedMsg struct{}

func (m Model) openPolicyViewer() (tea.Model, tea.Cmd) {
	return m.openPolicyEditor()
}

func (m Model) openPolicyEditor() (tea.Model, tea.Cmd) {
	target := m.defaultPolicyEditorTarget()
	m.policyEd.returnView = m.viewState
	m.policyEd.editor = nil
	m.policyEd.target = string(target)
	m.policyEd.loading = true
	m.policyEd.err = ""
	m.viewState = ViewPolicyEditor
	return m, m.loadPolicyEditorCmd(target)
}

func (m Model) loadPolicyEditorCmd(target policyeditor.Target) tea.Cmd {
	client := m.adminClient
	return func() tea.Msg {
		if client == nil {
			return policyEditorLoadedMsg{target: target, err: fmt.Errorf("admin client is not connected")}
		}
		store := &policyeditor.AdminStore{
			Client: policyeditor.NewProtocolClient(client, policyEditorRequestTimeout),
			Target: target,
		}
		stored, err := store.Load(context.Background())
		return policyEditorLoadedMsg{
			target: target,
			store:  store,
			stored: stored,
			err:    err,
		}
	}
}

func (m Model) defaultPolicyEditorTarget() policyeditor.Target {
	if m.admin.settings != nil && strings.EqualFold(strings.TrimSpace(m.admin.settings.NodeRole), "sentry") {
		return policyeditor.TargetSentry
	}
	return policyeditor.TargetSigner
}

func (m Model) handlePolicyEditorLoaded(msg policyEditorLoadedMsg) (tea.Model, tea.Cmd) {
	if m.viewState != ViewPolicyEditor {
		return m, nil
	}
	m.policyEd.loading = false
	m.policyEd.err = ""
	if msg.err != nil {
		m.policyEd.err = msg.err.Error()
		m.lastError = "Policy editor failed: " + msg.err.Error()
		return m, nil
	}
	identityID := msg.store.IdentityID()
	if identityID == "" {
		identityID = "default"
	}
	editor := policytui.NewWithTarget(msg.store, msg.stored, "apsigner admin protocol", identityID, msg.target)
	editorModel, cmd := editor.Update(tea.WindowSizeMsg{Width: m.width, Height: m.policyEditorHeight()})
	m.policyEd.editor = editorModel
	return m, wrapPolicyEditorCmd(cmd)
}

func (m Model) handlePolicyEditorKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.policyEd.editor == nil {
		switch msg.String() {
		case "esc", "q":
			return m.closePolicyEditor()
		case "r", "R":
			target := m.defaultPolicyEditorTarget()
			if m.policyEd.target != "" {
				target = policyeditor.Target(m.policyEd.target)
			}
			m.policyEd.loading = true
			m.policyEd.err = ""
			return m, m.loadPolicyEditorCmd(target)
		default:
			return m, nil
		}
	}
	return m.forwardPolicyEditorMsg(msg)
}

func (m Model) forwardPolicyEditorMsg(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.policyEd.editor == nil {
		return m, nil
	}
	editor, cmd := m.policyEd.editor.Update(msg)
	m.policyEd.editor = editor
	return m, wrapPolicyEditorCmd(cmd)
}

func (m Model) closePolicyEditor() (tea.Model, tea.Cmd) {
	if m.policyEd.returnView == 0 || m.policyEd.returnView == ViewPolicyEditor {
		m.policyEd.returnView = ViewAdminPanel
	}
	m.viewState = m.policyEd.returnView
	m.policyEd.editor = nil
	m.policyEd.loading = false
	m.policyEd.err = ""
	m.policyEd.target = ""
	return m, nil
}

func (m Model) renderPolicyEditor() string {
	if m.policyEd.loading {
		return titleStyle.Render("Policy") + "\n" + subtitleStyle.Render("Loading policy editor...")
	}
	if m.policyEd.err != "" {
		return titleStyle.Render("Policy") + "\n" + errorStyle.Render(m.policyEd.err)
	}
	if m.policyEd.editor == nil {
		return titleStyle.Render("Policy") + "\n" + subtitleStyle.Render("No policy editor loaded")
	}
	return m.policyEd.editor.View()
}

func (m Model) policyEditorFooterText() string {
	if m.policyEd.loading {
		return "loading policy editor"
	}
	if m.policyEd.err != "" || m.policyEd.editor == nil {
		return "r: Retry | esc/q: Back"
	}
	return "policy editor: q/esc: Back | v: Validate | a: Apply | w: Write draft"
}

func (m Model) policyEditorHeight() int {
	h := m.windowBodyHeight()
	if h < 1 {
		return 1
	}
	return h
}

func wrapPolicyEditorCmd(cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	return func() tea.Msg {
		return wrapPolicyEditorMsg(cmd())
	}
}

func wrapPolicyEditorMsg(msg tea.Msg) tea.Msg {
	switch msg := msg.(type) {
	case tea.QuitMsg:
		return policyEditorClosedMsg{}
	case tea.BatchMsg:
		wrapped := make(tea.BatchMsg, 0, len(msg))
		for _, cmd := range msg {
			if wrappedCmd := wrapPolicyEditorCmd(cmd); wrappedCmd != nil {
				wrapped = append(wrapped, wrappedCmd)
			}
		}
		return wrapped
	default:
		return msg
	}
}
