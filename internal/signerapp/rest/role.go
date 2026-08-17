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

func requireAccountSigningRole(ir *identity.Runtime, operation string) *signersigning.ServiceError {
	role := ir.NodeRole()
	switch role {
	case noderole.RoleSigner:
		return nil
	case noderole.RoleSentry:
		return &signersigning.ServiceError{
			Kind:    signersigning.ErrorForbidden,
			Message: fmt.Sprintf("node role %q does not allow %s", role, operation),
		}
	default:
		return &signersigning.ServiceError{
			Kind:    signersigning.ErrorForbidden,
			Message: fmt.Sprintf("unknown node role %q does not allow %s", role, operation),
		}
	}
}

func requireComponentNodeRole(ir *identity.Runtime, role signerapi.ComponentSignRole) *signersigning.ServiceError {
	nodeRole := ir.NodeRole()
	switch role {
	case signerapi.ComponentSignRoleSentry:
		switch nodeRole {
		case noderole.RoleSentry:
			return nil
		case noderole.RoleSigner:
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("node role %q does not allow sentry component signing", nodeRole),
			}
		default:
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("unknown node role %q does not allow sentry component signing", nodeRole),
			}
		}
	case signerapi.ComponentSignRoleUser:
		switch nodeRole {
		case noderole.RoleSigner:
			return nil
		case noderole.RoleSentry:
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("node role %q does not allow user component signing", nodeRole),
			}
		default:
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("unknown node role %q does not allow user component signing", nodeRole),
			}
		}
	default:
		return &signersigning.ServiceError{
			Kind:    signersigning.ErrorBadRequest,
			Message: fmt.Sprintf("unsupported component signing role %q", role),
		}
	}
}

func requireComponentTargetNodeRole(ir *identity.Runtime, kind signerapi.ComponentTargetKind) *signersigning.ServiceError {
	if kind == signerapi.ComponentTargetKindSentry {
		return requireComponentNodeRole(ir, signerapi.ComponentSignRoleSentry)
	}
	if kind == signerapi.ComponentTargetKindUser || kind == signerapi.ComponentTargetKindBoundedBase {
		return requireAccountSigningRole(ir, "account component signing")
	}
	return &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: fmt.Sprintf("unsupported component target kind %q", kind)}
}
