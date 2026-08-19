// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package auth

import (
	"context"
	"errors"
)

// Common authorization errors
var (
	// ErrUnauthorized indicates the identity is not authorized for the action
	ErrUnauthorized = errors.New("not authorized")

	// ErrForbidden indicates the action is forbidden for this identity
	ErrForbidden = errors.New("forbidden")
)

// Action represents an operation being performed
type Action string

// Common actions
const (
	ActionIdentityView       Action = "identity.view"
	ActionIdentityUnlock     Action = "identity.unlock"
	ActionIdentityBackup     Action = "identity.backup"
	ActionIdentityRestore    Action = "identity.restore"
	ActionIdentityLock       Action = "identity.lock"
	ActionIdentityPassphrase Action = "identity.passphrase"
	ActionSignRequest        Action = "sign.request"
	ActionSignApprove        Action = "sign.approve"
	ActionSignComponent      Action = "sign.component"
	ActionSignAssemble       Action = "sign.assemble"
	ActionKeysView           Action = "keys.view"
	ActionKeysGenerate       Action = "keys.generate"
	ActionKeysImport         Action = "keys.import"
	ActionKeysExport         Action = "keys.export"
	ActionKeysDelete         Action = "keys.delete"
	ActionSentriesView       Action = "sentries.view"
	ActionSentriesManage     Action = "sentries.manage"
	ActionGenerationsView    Action = "generations.view"
	ActionKeyTypesView       Action = "keytypes.view"
	ActionKeyTypesActivate   Action = "keytypes.activate"
	ActionKeyTypesDeactivate Action = "keytypes.deactivate"
	ActionTemplatesView      Action = "templates.view"
	ActionTemplatesInstall   Action = "templates.install"
	ActionTemplatesRemove    Action = "templates.remove"
	ActionPolicyView         Action = "policy.view"
	ActionPolicyUpdate       Action = "policy.update"
	ActionSettingsView       Action = "settings.view"
	ActionSettingsUpdate     Action = "settings.update"
	ActionTokenProvision     Action = "token.provision"
	ActionTokenRevoke        Action = "token.revoke"
	ActionHealthGet          Action = "health.get"

	ActionSign      = ActionSignRequest
	ActionListKeys  = ActionKeysView
	ActionGetHealth = ActionHealthGet
)

var knownActions = map[Action]struct{}{
	ActionIdentityView:       {},
	ActionIdentityUnlock:     {},
	ActionIdentityBackup:     {},
	ActionIdentityRestore:    {},
	ActionIdentityLock:       {},
	ActionIdentityPassphrase: {},
	ActionSignRequest:        {},
	ActionSignApprove:        {},
	ActionSignComponent:      {},
	ActionSignAssemble:       {},
	ActionKeysView:           {},
	ActionKeysGenerate:       {},
	ActionKeysImport:         {},
	ActionKeysExport:         {},
	ActionKeysDelete:         {},
	ActionSentriesView:       {},
	ActionSentriesManage:     {},
	ActionGenerationsView:    {},
	ActionKeyTypesView:       {},
	ActionKeyTypesActivate:   {},
	ActionKeyTypesDeactivate: {},
	ActionTemplatesView:      {},
	ActionTemplatesInstall:   {},
	ActionTemplatesRemove:    {},
	ActionPolicyView:         {},
	ActionPolicyUpdate:       {},
	ActionSettingsView:       {},
	ActionSettingsUpdate:     {},
	ActionTokenProvision:     {},
	ActionTokenRevoke:        {},
	ActionHealthGet:          {},
}

// IsKnownAction reports whether action is part of the stable authorization
// vocabulary. Authorizers should reject unknown actions before grant matching so
// callsite or grant typos fail closed instead of becoming ad hoc permissions.
func IsKnownAction(action Action) bool {
	_, ok := knownActions[action]
	return ok
}

// Resource represents the target of an action
type Resource struct {
	// Type is the resource type ("key", "transaction", "system")
	Type string

	// ID is the resource identifier (e.g., key address)
	ID string
}

// Authorizer determines if an identity is allowed to perform an action on a resource
type Authorizer interface {
	// Authorize checks if the identity can perform the action on the resource.
	// Returns nil if authorized, ErrUnauthorized or ErrForbidden otherwise.
	Authorize(ctx context.Context, identity *Identity, action Action, resource Resource) error
}
