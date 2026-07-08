// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
)

func signingContextDetailsFromEngine(signingCtx *engine.SigningContext) SigningContextDetails {
	if signingCtx == nil {
		return SigningContextDetails{}
	}
	return SigningContextDetails{
		Address:        signingCtx.Address,
		SigningAddress: signingCtx.SigningAddr,
		KeyType:        signingCtx.KeyType,
		SigSize:        signingCtx.SigSize,
		IsLogicSig:     signingCtx.IsLSig,
		DisplayKeyType: displaySigningKeyType(signingCtx.KeyType, signingCtx.IsLSig),
	}
}

// displaySigningKeyType renders the human-readable signing key-type label.
// Presentation lives here in the UI layer, not in the engine.
func displaySigningKeyType(keyType string, isLogicSig bool) string {
	if isLogicSig {
		return keytypefmt.Display(keyType) + " lsig"
	}
	return "Ed25519 key"
}

// ResolveSigningContext resolves the signer-facing signing context for an address or alias.
func (a *App) ResolveSigningContext(ctx context.Context, addressOrAlias string) (*SigningContextResult, error) {
	result := &SigningContextResult{}

	resolver := a.eng.NewAddressResolver()
	if address, err := resolver.ResolveSingle(addressOrAlias); err == nil {
		result.IsRekeyed, result.AuthAddress = a.eng.IsRekeyed(address)
	}

	signingCtx, err := a.eng.BuildSigningContext(ctx, addressOrAlias)
	if err != nil {
		return nil, err
	}

	result.SigningContext = signingContextDetailsFromEngine(signingCtx)
	return result, nil
}
