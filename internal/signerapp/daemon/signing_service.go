// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapp/externalcheck"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	"github.com/aplane-algo/aplane/internal/signerapp/txdesc"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

type signingAudit interface {
	signersigning.AuditLogger
	signersigning.AuditApproveLogger
	signersigning.AuditRejectLogger
	signersigning.AuditFailLogger
}

func (fs *Signer) newSigningServiceWithAudit(ir *productruntime.Runtime, auditLog signingAudit) *signersigning.Service {
	// One request, one session: the request signs only while the signer is
	// unlocked in the session it began in. A recovery and a reconcile while
	// it waits for approval end that session as a lock does, so the request
	// is refused rather than signed on a plan from before them. It is read
	// before the policy snapshot below, and the caller builds the service
	// before it takes the request's key session, so both belong to this
	// session or the request is refused. A request that begins while the
	// signer is not unlocked has no session: the one a recovery opens is
	// unlocked again by its reconcile, after a policy snapshot taken now may
	// have been replaced, so such a request is refused for good.
	generation, unlocked := ir.UnlockedGeneration()
	inSession := func() bool { return unlocked && ir.IsUnlockedIn(generation) }

	// One request, one policy snapshot: every slot of this request resolves
	// against the NodePolicy captured here, whatever reloads land later, and
	// its approval prompts show amounts from the context it was loaded in.
	nodePolicy := ir.NodePolicy()
	var describe signersigning.DescribeTxnFunc = fs.generateTransactionDescriptionFromTxn
	if nodePolicy != nil && nodePolicy.Context != nil {
		ctx := nodePolicy.Context
		describe = func(txn types.Transaction) txnreview.Details { return txdesc.DetailTxnInContext(txn, ctx) }
	}
	return &signersigning.Service{
		Planner:                       fs.newPlannerWithAudit(auditLog),
		Approval:                      fs.newApprovalServiceWithAudit(ir, auditLog),
		Executor:                      fs.newExecutionServiceWithAudit(auditLog),
		AuditLog:                      auditLog,
		GenerateTxnDescriptionFromTxn: describe,
		IsUnlocked:                    inSession,
		PolicyFor:                     nodePolicy.PolicyFor,
		HoldsCosignerKey: func(witnessKeyID string) bool {
			_, err := ir.FindKeyFile(witnessKeyID)
			return err == nil
		},
		Rotating: fs.rotatingDeps(ir),
		// Tokens are read from the index published at the time of the
		// lookup, inside the step's key use: a lock waits for the step
		// before it zeroes the index. A token read here becomes a request
		// header, a Go string that cannot be zeroed (see SourceTokenFor).
		ExternalChecks: &externalcheck.Runner{Fetcher: &fs.externalFetcher, Tokens: ir.SourceTokenFor},
		KeyUse:         ir.KeyUseContext,
	}
}
