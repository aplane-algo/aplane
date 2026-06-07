// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
)

// RegistryAuthenticator authenticates HTTP requests by scanning all registered
// identity authenticators. On a match, the request identity is set to the
// matching identity's ID. This is an O(n) bounded scan suitable for small
// numbers of identities.
type RegistryAuthenticator struct {
	registry *Registry
}

// NewRegistryAuthenticator creates an authenticator that resolves tokens
// against all registered identities.
func NewRegistryAuthenticator(r *Registry) *RegistryAuthenticator {
	return &RegistryAuthenticator{registry: r}
}

// Authenticate tries each identity's authenticator and requires exactly one match.
// Returns the identity from the single matching authenticator. If no authenticator
// matches, returns the error from the last attempt. If multiple match (duplicate
// tokens across identities), returns an error to prevent nondeterministic routing.
func (ra *RegistryAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	if err := ra.registry.CloseError(); err != nil {
		return nil, err
	}
	runtimes := ra.registry.All()
	if len(runtimes) == 0 {
		return nil, auth.ErrNoCredentials
	}

	var matched *auth.Identity
	var matchedID string
	var matchCount int
	var lastErr error

	for _, ir := range runtimes {
		if ir == nil || ir.IsDecommissioned() {
			continue
		}
		a := ir.Authenticator()
		if a == nil {
			continue
		}
		ident, err := a.Authenticate(ctx, r)
		if err == nil {
			matchCount++
			if matchCount == 1 {
				ident.ID = ir.ID()
				matched = ident
				matchedID = ir.ID()
			}
			_ = matchedID // used only for the single-match path
		} else {
			lastErr = err
		}
	}

	if matchCount > 1 {
		return nil, fmt.Errorf("ambiguous token: matches multiple identities")
	}
	if matchCount == 1 {
		return matched, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if r.Header.Get("Authorization") != "" {
		return nil, auth.ErrInvalidCredentials
	}
	return nil, auth.ErrNoCredentials
}

// Method returns "aplane-token" since all identity authenticators use that method.
func (ra *RegistryAuthenticator) Method() string {
	return "aplane-token"
}
