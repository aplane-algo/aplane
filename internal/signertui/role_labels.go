// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
)

func (m Model) nodeRole() string {
	role := m.initialNodeRole
	if m.admin.settings != nil && strings.TrimSpace(m.admin.settings.NodeRole) != "" {
		role = m.admin.settings.NodeRole
	}
	return strings.ToLower(strings.TrimSpace(role))
}

func (m Model) isSentryNode() bool {
	return m.nodeRole() == "sentry"
}

func (m Model) nodeRoleNoun() string {
	if m.isSentryNode() {
		return "Sentry"
	}
	return "Signer"
}

func (m Model) rolePortLabel() string {
	return m.nodeRoleNoun() + " Port"
}

func (m Model) keyIdentifierLabel(keyType string) string {
	if m.isSentryNode() || keytypes.IsSentryComponentKeyType(keyType) {
		return "Sentry Key"
	}
	return "Address"
}
