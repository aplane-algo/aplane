// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"slices"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
)

// boundedSigningWorkflow names a bounded workflow whose spending proofs the signer
// verifies for an existing account.
type boundedSigningWorkflow int

const (
	boundedWorkflowCosigner boundedSigningWorkflow = iota + 1
)

// boundedSigningConstructions lists, for each durable contract and workflow, the
// spending constructions this signer's code completes: the receipt and component
// choreography for a cosigner, on Falcon or Ed25519 for both a bounded and a
// plain host.
//
// This is a fact about the signing implementation, so it is kept apart from the
// generation admission policy in composeddsa. Admission decides which accounts
// may be created and may narrow over time. Signing must keep completing every
// account that was created, so it never reads that policy. Admission must stay
// within this table, or it would create accounts the signer cannot complete;
// TestBoundedGenerationAdmitsOnlySignableWorkflows pins that.
var boundedSigningConstructions = map[string]map[boundedSigningWorkflow][]sigconstruction.ConstructionID{
	boundedmeta.Contract: {
		boundedWorkflowCosigner: {sigconstruction.Falcon1024().ID(), sigconstruction.Ed25519().ID()},
	},
	boundedmeta.PlainContract: {
		boundedWorkflowCosigner: {sigconstruction.Falcon1024().ID(), sigconstruction.Ed25519().ID()},
	},
}

// boundedSpendingConstruction resolves an existing account's spending construction
// for a workflow from its durable contract and base_key_type. A base the workflow
// can't complete has no construction here, so callers refuse it at the point
// where a failed verification is refused.
func boundedSpendingConstruction(contract, baseKeyType string, workflow boundedSigningWorkflow) (sigconstruction.Construction, bool) {
	construction, ok := sigconstruction.ForBaseKeyType(baseKeyType)
	if !ok {
		return sigconstruction.Construction{}, false
	}
	if !slices.Contains(boundedSigningConstructions[contract][workflow], construction.ID()) {
		return sigconstruction.Construction{}, false
	}
	return construction, true
}

// boundedLayoutMatches reports whether an account's durable base-signature layout is
// exactly its construction's layout. Generation writes the construction's layout, so a
// difference means stored metadata and the catalog disagree, and the proof is refused
// rather than checked against one of them.
func boundedLayoutMatches(construction sigconstruction.Construction, durable boundedmeta.SignatureArgLayout) bool {
	layout := construction.Layout()
	return durable.Count == layout.Count() && slices.Equal(durable.MaxSizes, layout.MaxSizes())
}
