// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func requireAccountSigningRole(ir *productruntime.Runtime, operation string) *signersigning.ServiceError {
	role := ir.NodeRole()
	switch role {
	case noderole.RoleSigner:
		return nil
	case noderole.RoleCosigner:
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

func requireComponentNodeRole(ir *productruntime.Runtime, role signersigning.ComponentSignRole) *signersigning.ServiceError {
	nodeRole := ir.NodeRole()
	switch role {
	case signersigning.ComponentSignRoleCosigner:
		switch nodeRole {
		case noderole.RoleCosigner:
			return nil
		case noderole.RoleSigner:
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("node role %q does not allow cosigner component signing", nodeRole),
			}
		default:
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("unknown node role %q does not allow cosigner component signing", nodeRole),
			}
		}
	case signersigning.ComponentSignRoleUser:
		switch nodeRole {
		case noderole.RoleSigner:
			return nil
		case noderole.RoleCosigner:
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

func requireComponentTargetNodeRole(ir *productruntime.Runtime, kind signerapi.ComponentTargetKind) *signersigning.ServiceError {
	if kind == signerapi.ComponentTargetKindCosigner {
		return requireComponentNodeRole(ir, signersigning.ComponentSignRoleCosigner)
	}
	if kind == signerapi.ComponentTargetKindUser || kind == signerapi.ComponentTargetKindBoundedBase {
		return requireAccountSigningRole(ir, "account component signing")
	}
	return &signersigning.ServiceError{Kind: signersigning.ErrorForbidden, Message: fmt.Sprintf("unsupported component target kind %q", kind)}
}
