// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
)

// hostWorkflowSupport records which bounded workflows have been reviewed for a
// spending base under a contract. A listed base supports ordinary spending and
// spending-key rekey.
type hostWorkflowSupport struct {
	cosigner bool
}

type hostSupportKey struct {
	contract     string
	construction sigconstruction.ConstructionID
}

// hostSupportPolicy decides whether a new account may be created with a
// profile. It is keyed by construction rather than by base name, so a registered
// base with no construction has no support. It answers no structural question.
//
// It is admission only. Signing an existing account never reads it, so narrowing
// it can't strand a credential: the signer keeps its own table of the workflows it
// completes (internal/signerapp/signing/host_construction.go), and this policy
// must stay within that table.
var hostSupportPolicy = map[hostSupportKey]hostWorkflowSupport{
	{hostmeta.BoundedContract, sigconstruction.Falcon1024().ID()}: {cosigner: true},
	// Reviewed with the plain hosts' bounds (account overlays phase 6.5), as
	// plain1 was in phase 5: an Ed25519 spending key is classical, which the
	// review says.
	{hostmeta.BoundedContract, sigconstruction.Ed25519().ID()}: {cosigner: true},
	// A plain host may be cosigned on either base. Its Ed25519 spending key is
	// classical, which the review says.
	{hostmeta.PlainContract, sigconstruction.Falcon1024().ID()}: {cosigner: true},
	{hostmeta.PlainContract, sigconstruction.Ed25519().ID()}:    {cosigner: true},
}

// hostGenerationPolicy answers the support question for one composer.
type hostGenerationPolicy func(contract, baseKeyType string) (hostWorkflowSupport, bool)

func productionHostGenerationPolicy(contract, baseKeyType string) (hostWorkflowSupport, bool) {
	construction, ok := sigconstruction.ForBaseKeyType(baseKeyType)
	if !ok {
		return hostWorkflowSupport{}, false
	}
	support, ok := hostSupportPolicy[hostSupportKey{contract, construction.ID()}]
	return support, ok
}

// checkHostGenerationSupport refuses a bounded program the current
// implementation could not operate, such as a cosigner on a base the cosigner
// workflow has not been reviewed for.
//
// This is an admission decision for new accounts, so it runs only from
// GenerateTEAL. It must stay out of ValidateTemplateSpec, validateHostConfig
// and their shared metadata helpers: installed templates reach those on load, and
// an error there changes their fingerprint and makes the store fail validation.
func (c *ComposedDSA) checkHostGenerationSupport() error {
	if c.host == nil {
		return nil
	}
	policy := c.generationPolicy
	if policy == nil {
		policy = productionHostGenerationPolicy
	}
	support, ok := policy(c.host.Contract, c.baseKeyType)
	if !ok {
		return fmt.Errorf("%s accounts cannot be generated on base key type %q", c.host.Contract, c.baseKeyType)
	}
	// The policy resolved the base by name, but the program verifies whatever the
	// ops render. A direct NewComposedDSA call bypasses RegisterBase, so check here
	// too that the two agree. Fixture composers carry their own policy and a base
	// name outside the catalog, so this only constrains production names.
	if err := baseConstructionAgrees(c.baseKeyType, c.ops); err != nil {
		return err
	}
	if c.host.Cosigner != nil && !support.cosigner {
		return fmt.Errorf("base key type %q does not support a cosigner under %s", c.baseKeyType, c.host.Contract)
	}
	return nil
}
