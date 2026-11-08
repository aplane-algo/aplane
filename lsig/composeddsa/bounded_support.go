// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/sigconstruction"
)

// boundedWorkflowSupport records which bounded workflows have been reviewed for a
// spending base under a contract. A listed base supports ordinary spending and
// spending-key rekey.
type boundedWorkflowSupport struct {
	cosigner bool
}

type boundedSupportKey struct {
	contract     string
	construction sigconstruction.ConstructionID
}

// boundedSupportPolicy decides whether a new account may be created with a
// profile. It is keyed by construction rather than by base name, so a registered
// base with no construction has no support. It answers no structural question.
//
// It is admission only. Signing an existing account never reads it, so narrowing
// it can't strand a credential: the signer keeps its own table of the workflows it
// completes (internal/signerapp/signing/bounded_construction.go), and this policy
// must stay within that table.
var boundedSupportPolicy = map[boundedSupportKey]boundedWorkflowSupport{
	{BoundedContractV1, sigconstruction.Falcon1024().ID()}: {cosigner: true},
	{BoundedContractV1, sigconstruction.Ed25519().ID()}:    {},
}

// boundedGenerationPolicy answers the support question for one composer.
type boundedGenerationPolicy func(contract, baseKeyType string) (boundedWorkflowSupport, bool)

func productionBoundedGenerationPolicy(contract, baseKeyType string) (boundedWorkflowSupport, bool) {
	construction, ok := sigconstruction.ForBaseKeyType(baseKeyType)
	if !ok {
		return boundedWorkflowSupport{}, false
	}
	support, ok := boundedSupportPolicy[boundedSupportKey{contract, construction.ID()}]
	return support, ok
}

// checkBoundedGenerationSupport refuses a bounded program the current
// implementation could not operate, such as a cosigner on a base the cosigner
// workflow has not been reviewed for.
//
// This is an admission decision for new accounts, so it runs only from
// GenerateTEAL. It must stay out of ValidateTemplateSpec, validateBoundedConfig
// and their shared metadata helpers: installed templates reach those on load, and
// an error there changes their fingerprint and makes the store fail validation.
func (c *ComposedDSA) checkBoundedGenerationSupport() error {
	if c.bounded == nil {
		return nil
	}
	policy := c.generationPolicy
	if policy == nil {
		policy = productionBoundedGenerationPolicy
	}
	support, ok := policy(c.bounded.Contract, c.baseKeyType)
	if !ok {
		return fmt.Errorf("%s accounts cannot be generated on base key type %q", c.bounded.Contract, c.baseKeyType)
	}
	// The policy resolved the base by name, but the program verifies whatever the
	// ops render. A direct NewComposedDSA call bypasses RegisterBase, so check here
	// too that the two agree. Fixture composers carry their own policy and a base
	// name outside the catalog, so this only constrains production names.
	if err := baseConstructionAgrees(c.baseKeyType, c.ops); err != nil {
		return err
	}
	if c.bounded.Cosigner != nil && !support.cosigner {
		return fmt.Errorf("base key type %q does not support a cosigner under %s", c.baseKeyType, c.bounded.Contract)
	}
	return nil
}
