// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policyeditor"
	"github.com/aplane-algo/aplane/internal/policytui"
	"github.com/aplane-algo/aplane/internal/protocol"
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

type adminPolicyClientAdapter struct {
	client  *IPCClient
	timeout time.Duration
}

func (c adminPolicyClientAdapter) GetPolicySnapshot(ctx context.Context, target policyeditor.Target) (policyeditor.AdminPolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return policyeditor.AdminPolicySnapshot{}, err
	}
	var out protocol.PolicySnapshotMessage
	err := c.request(protocol.GetPolicySnapshotMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGetPolicySnapshot,
			ID:   fmt.Sprintf("policy-snapshot-%d", time.Now().UnixNano()),
		},
		Target: string(target),
	}, &out)
	if err != nil {
		return policyeditor.AdminPolicySnapshot{}, err
	}
	return adminPolicySnapshotFromProtocol(out, target), nil
}

func (c adminPolicyClientAdapter) ValidatePolicy(ctx context.Context, target policyeditor.Target, policyYAML string) (policyeditor.AdminPolicyValidation, error) {
	if err := ctx.Err(); err != nil {
		return policyeditor.AdminPolicyValidation{}, err
	}
	var out protocol.ValidatePolicyResultMessage
	err := c.request(protocol.ValidatePolicyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeValidatePolicy,
			ID:   fmt.Sprintf("policy-validate-%d", time.Now().UnixNano()),
		},
		Target:     string(target),
		PolicyYAML: policyYAML,
	}, &out)
	if err != nil {
		return policyeditor.AdminPolicyValidation{}, err
	}
	resultTarget := policyeditor.Target(out.Target)
	if resultTarget == "" {
		resultTarget = target
	}
	return policyeditor.AdminPolicyValidation{
		Success:    out.Success,
		Target:     resultTarget,
		IdentityID: out.IdentityID,
		Code:       out.Code,
		Error:      out.Error,
	}, nil
}

func (c adminPolicyClientAdapter) ReplacePolicy(ctx context.Context, target policyeditor.Target, policyYAML, expectedCurrentSHA256 string) (policyeditor.AdminPolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return policyeditor.AdminPolicySnapshot{}, err
	}
	var out protocol.ReplacePolicyResultMessage
	err := c.request(protocol.ReplacePolicyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeReplacePolicy,
			ID:   fmt.Sprintf("policy-replace-%d", time.Now().UnixNano()),
		},
		Target:                string(target),
		PolicyYAML:            policyYAML,
		ExpectedCurrentSHA256: expectedCurrentSHA256,
	}, &out)
	if err != nil {
		return policyeditor.AdminPolicySnapshot{}, err
	}
	return adminPolicySnapshotFromProtocol(policySnapshotMessageFromReplace(out), target), nil
}

func (c adminPolicyClientAdapter) request(msg interface{}, out interface{}) error {
	if c.client == nil {
		return fmt.Errorf("admin client is not connected")
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = policyEditorRequestTimeout
	}
	raw, err := c.client.SendAndReceive(msg, timeout)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return err
	}
	return nil
}

func adminPolicySnapshotFromProtocol(msg protocol.PolicySnapshotMessage, requested policyeditor.Target) policyeditor.AdminPolicySnapshot {
	target := policyeditor.Target(msg.Target)
	if target == "" {
		target = requested
	}
	return policyeditor.AdminPolicySnapshot{
		Success:      msg.Success,
		Target:       target,
		IdentityID:   msg.IdentityID,
		PolicyYAML:   msg.PolicyYAML,
		PolicySHA256: msg.PolicySHA256,
		Canonical:    msg.Canonical,
		Code:         msg.Code,
		Error:        msg.Error,
	}
}

func policySnapshotMessageFromReplace(msg protocol.ReplacePolicyResultMessage) protocol.PolicySnapshotMessage {
	return protocol.PolicySnapshotMessage{
		BaseMessage:  msg.BaseMessage,
		Success:      msg.Success,
		Target:       msg.Target,
		IdentityID:   msg.IdentityID,
		PolicyYAML:   msg.PolicyYAML,
		PolicySHA256: msg.PolicySHA256,
		Canonical:    msg.Canonical,
		Code:         msg.Code,
		Error:        msg.Error,
	}
}

func (m Model) openPolicyViewer() (tea.Model, tea.Cmd) {
	return m.openPolicyEditor()
}

func (m Model) openPolicyEditor() (tea.Model, tea.Cmd) {
	target := m.defaultPolicyEditorTarget()
	m.policyEditorReturnView = m.viewState
	m.policyEditor = nil
	m.policyEditorTarget = string(target)
	m.policyEditorLoading = true
	m.policyEditorError = ""
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
			Client: adminPolicyClientAdapter{client: client, timeout: policyEditorRequestTimeout},
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
	if m.adminSettings != nil && strings.EqualFold(strings.TrimSpace(m.adminSettings.NodeRole), "attestor") {
		return policyeditor.TargetAttestation
	}
	return policyeditor.TargetSigner
}

func (m Model) handlePolicyEditorLoaded(msg policyEditorLoadedMsg) (tea.Model, tea.Cmd) {
	if m.viewState != ViewPolicyEditor {
		return m, nil
	}
	m.policyEditorLoading = false
	m.policyEditorError = ""
	if msg.err != nil {
		m.policyEditorError = msg.err.Error()
		m.lastError = "Policy editor failed: " + msg.err.Error()
		return m, nil
	}
	identityID := msg.store.IdentityID()
	if identityID == "" {
		identityID = "default"
	}
	editor := policytui.NewWithTarget(msg.store, msg.stored, "apsigner admin protocol", identityID, msg.target)
	editorModel, cmd := editor.Update(tea.WindowSizeMsg{Width: m.width, Height: m.policyEditorHeight()})
	m.policyEditor = editorModel
	return m, wrapPolicyEditorCmd(cmd)
}

func (m Model) handlePolicyEditorKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.policyEditor == nil {
		switch msg.String() {
		case "esc", "q":
			return m.closePolicyEditor()
		case "r", "R":
			target := m.defaultPolicyEditorTarget()
			if m.policyEditorTarget != "" {
				target = policyeditor.Target(m.policyEditorTarget)
			}
			m.policyEditorLoading = true
			m.policyEditorError = ""
			return m, m.loadPolicyEditorCmd(target)
		default:
			return m, nil
		}
	}
	return m.forwardPolicyEditorMsg(msg)
}

func (m Model) forwardPolicyEditorMsg(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.policyEditor == nil {
		return m, nil
	}
	editor, cmd := m.policyEditor.Update(msg)
	m.policyEditor = editor
	return m, wrapPolicyEditorCmd(cmd)
}

func (m Model) closePolicyEditor() (tea.Model, tea.Cmd) {
	if m.policyEditorReturnView == 0 || m.policyEditorReturnView == ViewPolicyEditor {
		m.policyEditorReturnView = ViewAdminPanel
	}
	m.viewState = m.policyEditorReturnView
	m.policyEditor = nil
	m.policyEditorLoading = false
	m.policyEditorError = ""
	m.policyEditorTarget = ""
	return m, nil
}

func (m Model) renderPolicyEditor() string {
	if m.policyEditorLoading {
		return titleStyle.Render("Policy") + "\n" + subtitleStyle.Render("Loading policy editor...")
	}
	if m.policyEditorError != "" {
		return titleStyle.Render("Policy") + "\n" + errorStyle.Render(m.policyEditorError)
	}
	if m.policyEditor == nil {
		return titleStyle.Render("Policy") + "\n" + subtitleStyle.Render("No policy editor loaded")
	}
	return m.policyEditor.View()
}

func (m Model) policyEditorFooterText() string {
	if m.policyEditorLoading {
		return "loading policy editor"
	}
	if m.policyEditorError != "" || m.policyEditor == nil {
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
