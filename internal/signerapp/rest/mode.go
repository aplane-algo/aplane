// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

func requireAccountSigningMode(ir *identity.Runtime, operation string) *signersigning.ServiceError {
	mode := ir.Config().Mode()
	if mode == identity.ModeAttestation {
		return &signersigning.ServiceError{
			Kind:    signersigning.ErrorForbidden,
			Message: fmt.Sprintf("identity mode %q does not allow %s", mode, operation),
		}
	}
	return nil
}

func requireComponentRoleMode(ir *identity.Runtime, role signerapi.ComponentSignRole) *signersigning.ServiceError {
	mode := ir.Config().Mode()
	switch role {
	case signerapi.ComponentSignRoleAttestor:
		if mode == identity.ModeSigning {
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("identity mode %q does not allow attestor component signing", mode),
			}
		}
	case signerapi.ComponentSignRoleUser:
		if mode == identity.ModeAttestation {
			return &signersigning.ServiceError{
				Kind:    signersigning.ErrorForbidden,
				Message: fmt.Sprintf("identity mode %q does not allow user component signing", mode),
			}
		}
	}
	return nil
}
