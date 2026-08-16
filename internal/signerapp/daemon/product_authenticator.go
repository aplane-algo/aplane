// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/authz"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

// productAuthenticator verifies the one product runtime's token and maps the
// credential to the reserved product-admin principal. Token authentication is
// deliberately independent from runtime selection.
type productAuthenticator struct {
	registry *identity.Registry
	runtime  *identity.Runtime
}

func newProductAuthenticator(registry *identity.Registry, runtime *identity.Runtime) *productAuthenticator {
	return &productAuthenticator{registry: registry, runtime: runtime}
}

func (a *productAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	if a.registry != nil {
		if err := a.registry.CloseError(); err != nil {
			return nil, err
		}
	}
	if a.runtime == nil || a.runtime.Authenticator() == nil {
		return nil, auth.ErrInvalidCredentials
	}
	if _, err := a.runtime.Authenticator().Authenticate(ctx, r); err != nil {
		return nil, err
	}
	return authz.NewProductPrincipalIdentity(a.Method()), nil
}

func (*productAuthenticator) Method() string { return "aplane-token" }

var _ auth.Authenticator = (*productAuthenticator)(nil)
