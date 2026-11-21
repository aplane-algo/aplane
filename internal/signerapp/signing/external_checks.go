// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/externalcheck"
)

// ExternalCheckRunner runs a cosigner document's external checks for a
// request: nil when every check passes, the first refusal otherwise.
type ExternalCheckRunner interface {
	Run(ctx context.Context, cfg *policy.Config, req externalcheck.Request) (*externalcheck.Summary, *externalcheck.Refusal)
}

// runExternalChecks is the last cosigner gate. The policy has said sign; the
// document's external checks may still refuse. Nothing is looked up for a
// request an earlier gate refused, so transaction facts leave the node only
// when the answer is not already no.
//
// The step holds a key use while it runs: it reads source tokens and sends
// them. A lock cancels the key use's context, which ends every lookup at
// once, and waits for the release before it clears the tokens. So no lookup
// reads a token while it is being cleared, and none is sent after the lock.
func (s *Service) runExternalChecks(ctx context.Context, plan *ComponentSignPlan, cfg *policy.Config, group []types.Transaction, targets []int) *ServiceError {
	if len(cfg.ExternalChecks) == 0 {
		return nil
	}
	if s.ExternalChecks == nil {
		return s.refuseExternalCheck(plan, &externalcheck.Refusal{
			CheckID: cfg.ExternalChecks[0].ID, Outcome: policy.ExternalCheckUnavailableOutcome,
			Unit: "the request", Detail: "this node cannot run external checks",
		})
	}
	stepCtx, release := ctx, func() {}
	if s.KeyUse != nil {
		stepCtx, release = s.KeyUse(ctx)
	}
	defer release()
	resolver := s.genesisHashResolver()
	summary, refusal := s.ExternalChecks.Run(stepCtx, cfg, externalcheck.Request{
		WitnessKey: plan.ComponentKey,
		Group:      group,
		Targets:    targets,
		NetworkOf: func(txn types.Transaction) string {
			network, _ := resolver.NetworkForGenesisHashBytes(txn.GenesisHash[:])
			return network
		},
	})
	if refusal == nil {
		plan.ExternalChecks = summary
		return nil
	}
	// A step that ended because the request was canceled or the node locked
	// is reported as that, not as a refusal by a source.
	if err := ctx.Err(); err != nil {
		return canceledSignRequest(err)
	}
	if stepCtx.Err() != nil {
		return lockedError()
	}
	return s.refuseExternalCheck(plan, refusal)
}

// refuseExternalCheck records a refusal in full and tells the requester only
// which check refused which unit.
func (s *Service) refuseExternalCheck(plan *ComponentSignPlan, refusal *externalcheck.Refusal) *ServiceError {
	s.logCosignerRejections(plan, auditCosignerPolicyRejected+refusal.AuditReason(), refusal.RuleID())
	return forbidden("cosigner policy rejected request: " + refusal.Message())
}

// externalChecksNote is what a signed request's audit record says of the
// checks that ran for it.
func externalChecksNote(summary *externalcheck.Summary) string {
	if summary == nil {
		return ""
	}
	if len(summary.CheckIDs) == 0 {
		return "; no external check applied"
	}
	lookups := "lookups"
	if summary.Lookups == 1 {
		lookups = "lookup"
	}
	return fmt.Sprintf("; external checks passed: %s (%d %s)", strings.Join(summary.CheckIDs, ", "), summary.Lookups, lookups)
}
