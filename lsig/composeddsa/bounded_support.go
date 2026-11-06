// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
)

// boundedWorkflowSupport records which bounded workflows have been reviewed for a
// spending base under a contract. A listed base supports ordinary spending and
// spending-key rekey.
type boundedWorkflowSupport struct {
	externalAdmin bool
	cosigner      bool
}

type boundedSupportKey struct {
	contract    string
	baseKeyType string
}

// boundedSupportPolicy decides whether a new account may be created with a
// profile. It is keyed by what generation already knows, and answers no
// structural question.
var boundedSupportPolicy = map[boundedSupportKey]boundedWorkflowSupport{
	{BoundedContractV1, "aplane.falcon1024.v1"}: {externalAdmin: true, cosigner: true},
	{BoundedContractV1, "aplane.ed25519.v1"}:    {},
}

// checkBoundedGenerationSupport refuses a bounded program the current
// implementation could not operate, such as an external-admin rekey on a base
// the admin ceremony cannot complete.
//
// This is an admission decision for new accounts, so it runs only from
// GenerateTEAL. It must stay out of ValidateTemplateSpec, validateBoundedConfig
// and their shared metadata helpers: installed templates reach those on load, and
// an error there changes their fingerprint and makes the store fail validation.
func (c *ComposedDSA) checkBoundedGenerationSupport() error {
	if c.bounded == nil {
		return nil
	}
	support, ok := boundedSupportPolicy[boundedSupportKey{c.bounded.Contract, c.baseKeyType}]
	if !ok {
		return fmt.Errorf("%s accounts cannot be generated on base key type %q", c.bounded.Contract, c.baseKeyType)
	}
	if boundedRequiresAdminKey(c.bounded) && !support.externalAdmin {
		return fmt.Errorf("base key type %q does not support %s rekey under %s: the contract-admin ceremony requires a Falcon-1024 spending key",
			c.baseKeyType, boundedmeta.AdminAuthorizationAdmin, c.bounded.Contract)
	}
	if c.bounded.Cosigner != nil && !support.cosigner {
		return fmt.Errorf("base key type %q does not support a cosigner under %s", c.baseKeyType, c.bounded.Contract)
	}
	return nil
}
