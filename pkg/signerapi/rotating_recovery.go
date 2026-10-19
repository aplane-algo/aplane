// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

// Rotating account status and recovery (GET /status, POST /admin/rotating/recover).
//
// The signer keeps a cache of each rotating account's stage addresses and
// reads the account's authorizer from its own node in the background. An
// authorizer it cannot place, neither a stage it has derived nor a key it
// holds, is searched for under a bounded grant: automatically from a
// per-unlock allowance, or at an operator's request with the operator's own
// budget and an optional stage hint. Status reports the classification and
// the grant; recovery never changes what the signer signs.

// Authorizer classifications reported in RotatingAccountStatus.
const (
	// RotatingClassStage: the authorizer is a stage of the account (stage 0
	// or one the signer has derived).
	RotatingClassStage = "stage"
	// RotatingClassHeldKey: the authorizer is another credential this
	// signer holds; the account was rekeyed away from its rotating stages.
	RotatingClassHeldKey = "held_key"
	// RotatingClassUnknown: not a stage the signer has derived and not a
	// key it holds. A bounded search may still find the stage.
	RotatingClassUnknown = "unknown"
	// RotatingClassUnobserved: the signer could not read the account from
	// its node in the last pass.
	RotatingClassUnobserved = "unobserved"
)

// Recovery grant kinds and actions.
const (
	RotatingRecoveryAutomatic = "automatic"
	RotatingRecoveryOperator  = "operator"

	RotatingRecoverActionStart  = "start"
	RotatingRecoverActionCancel = "cancel"
)

// RotatingAccountStatus is one rotating account's view from the signer's
// last background pass.
type RotatingAccountStatus struct {
	Account string `json:"account"`
	// Authorizer is the address the node reported as the account's
	// authorizer; the account itself when none is set. Empty when the last
	// read failed.
	Authorizer string `json:"authorizer,omitempty"`
	Round      uint64 `json:"round,omitempty"`
	// Classification is one of the RotatingClass* values.
	Classification string `json:"classification"`
	// Stage is the live stage when Classification is "stage".
	Stage *uint64 `json:"stage,omitempty"`
	// CachedStages is how many stages, from 0, the signer's table covers.
	CachedStages uint64 `json:"cached_stages"`
	// Recovery is present once any search has been started or stopped for
	// the account in this unlock.
	Recovery *RotatingRecoveryStatus `json:"recovery,omitempty"`
}

// RotatingRecoveryStatus reports an account's stage recovery: the active
// grant if any, why the last one stopped, and the per-unlock automatic
// allowance.
type RotatingRecoveryStatus struct {
	// Active reports a grant in progress; the fields through FoundStage
	// describe it.
	Active        bool    `json:"active"`
	Kind          string  `json:"kind,omitempty"`
	GrantID       uint64  `json:"grant_id,omitempty"`
	StagesCharged uint64  `json:"stages_charged,omitempty"`
	MaxStages     uint64  `json:"max_stages,omitempty"`
	ActiveSeconds int64   `json:"active_seconds,omitempty"`
	Hint          *uint64 `json:"hint,omitempty"`
	// FoundStage is set once a hinted search matched the authorizer; the
	// grant is then filling the cache up to that stage.
	FoundStage *uint64 `json:"found_stage,omitempty"`

	// Stopped is why the last grant ended, with its kind, ID and, when it
	// found the stage, that stage.
	Stopped        string  `json:"stopped,omitempty"`
	StoppedKind    string  `json:"stopped_kind,omitempty"`
	StoppedGrantID uint64  `json:"stopped_grant_id,omitempty"`
	StoppedStage   *uint64 `json:"stopped_stage,omitempty"`

	// AllowanceSpent and AllowanceMax are the automatic per-unlock allowance
	// (rotating.recovery_max_stages); AllowanceMax 0 means automatic
	// recovery is disabled. SuppressedAuthorizer names the authorizer for
	// which automatic recovery has been exhausted in this unlock.
	AllowanceSpent       uint64 `json:"allowance_spent"`
	AllowanceMax         uint64 `json:"allowance_max"`
	SuppressedAuthorizer string `json:"suppressed_authorizer,omitempty"`
}

// RotatingRecoverRequest starts or cancels an operator recovery grant
// (POST /admin/rotating/recover). Start derives from the stage table's edge
// until the authorizer appears, or, with a hint, probes the hinted stage and
// its neighbours within Window and then fills the table up to the stage it
// found. The grant ends when the stage is found, MaxStages derivations are
// spent, TimeoutSeconds of derivation time pass, or it is cancelled.
type RotatingRecoverRequest struct {
	Account string `json:"account"`
	// Action is "start" or "cancel".
	Action string `json:"action"`
	// Stage is the hint: the stage the operator believes is live. Optional.
	Stage *uint64 `json:"stage,omitempty"`
	// Window is how many stages on each side of the hint to probe (default
	// 64, at most 4096). Ignored without a hint.
	Window uint64 `json:"window,omitempty"`
	// MaxStages is the grant's derivation budget (default 4096).
	MaxStages uint64 `json:"max_stages,omitempty"`
	// TimeoutSeconds caps the grant's derivation time (default 300).
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`
}

// RotatingRecoverResponse reports the grant started or cancelled and the
// account's recovery status after the request.
type RotatingRecoverResponse struct {
	Account string `json:"account"`
	Action  string `json:"action"`
	// GrantID is the grant started, or the one cancelled; 0 on a cancel
	// that found nothing to cancel.
	GrantID  uint64                 `json:"grant_id,omitempty"`
	Recovery RotatingRecoveryStatus `json:"recovery"`
}

// Validate checks the request shape.
func (r RotatingRecoverRequest) Validate() error {
	if r.Account == "" {
		return fmt.Errorf("account is required")
	}
	switch r.Action {
	case RotatingRecoverActionStart, RotatingRecoverActionCancel:
	default:
		return fmt.Errorf("action must be %q or %q", RotatingRecoverActionStart, RotatingRecoverActionCancel)
	}
	if r.TimeoutSeconds < 0 {
		return fmt.Errorf("timeout_seconds must not be negative")
	}
	return nil
}
