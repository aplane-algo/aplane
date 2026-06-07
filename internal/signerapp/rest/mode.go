// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func requireAccountSigningMode(ir *identity.Runtime, operation string) *signersigning.ServiceError {
	role := ir.NodeRole()
	if role == noderole.RoleAttestor {
		return &signersigning.ServiceError{
			Kind:    signersigning.ErrorForbidden,
			Message: fmt.Sprintf("node role %q does not allow %s", role, operation),
		}
	}
	return nil
}

func requireComponentRoleMode(ir *identity.Runtime, role signerapi.ComponentSignRole) *signersigning.ServiceError {
	nodeRole := ir.NodeRole()
	switch role {
	case signerapi.ComponentSignRoleAttestor:
		if nodeRole == noderole.RoleSigner {
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("node role %q does not allow attestor component signing", nodeRole),
			}
		}
	case signerapi.ComponentSignRoleUser:
		if nodeRole == noderole.RoleAttestor {
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("node role %q does not allow user component signing", nodeRole),
			}
		}
	}
	return nil
}
