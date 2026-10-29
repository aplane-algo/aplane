// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// IsRotatingAccount reports whether the signer serves address through the
// rotating1 flow.
func (e *Engine) IsRotatingAccount(address string) bool {
	return e.signerCacheSigningFlow(address) == signerapi.SigningFlowRotating1
}

// RotatingAccounts lists the signable rotating accounts.
func (e *Engine) RotatingAccounts() []string {
	var out []string
	for _, address := range e.GetSignableAddresses() {
		if e.IsRotatingAccount(address) {
			out = append(out, address)
		}
	}
	return out
}

// SignerStatusLines returns the signer's authenticated status warnings and
// notes, which include its rotating account alerts and in-flight releases.
func (e *Engine) SignerStatusLines(ctx context.Context) (warnings, notes []string, err error) {
	if !e.IsConnected() {
		return nil, nil, ErrNotConnected
	}
	status, err := e.Connection.GetSignerStatusWithContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	return status.Warnings, status.Notes, nil
}

// SignerRotatingStatus returns the signer's per-account rotating status
// from its last background pass, alongside the status warnings and notes.
func (e *Engine) SignerRotatingStatus(ctx context.Context) (accounts []signerapi.RotatingAccountStatus, warnings, notes []string, err error) {
	if !e.IsConnected() {
		return nil, nil, nil, ErrNotConnected
	}
	status, err := e.Connection.GetSignerStatusWithContext(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return status.Rotating, status.Warnings, status.Notes, nil
}

// RotatingRecover asks the signer to start or cancel a bounded search for a
// rotating account's live stage. No transaction is involved: the signer
// derives stage addresses into its own cache.
func (e *Engine) RotatingRecover(ctx context.Context, req signerapi.RotatingRecoverRequest) (*signerapi.RotatingRecoverResponse, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	return e.Connection.RotatingRecoverWithContext(ctx, req)
}

// rotatingSlot returns the position of the rotating account's transaction
// in txns, or -1 when no sender is a rotating account. A rotating spend may
// be grouped with transactions the signer signs with ordinary keys: every
// other transaction is judged on its effective signing authority, the key
// the auth cache resolves for its sender, so a sender rekeyed to a held key
// needs no credential of its own. That authority must be held, and must not
// be a rotating, witness, guarded or bounded key, which the rotating flow
// cannot sign alongside a rotation. The rotating account itself is found by
// sender: its authorizer is a stage address the signer never lists.
func (e *Engine) rotatingSlot(txns []types.Transaction, opts clientsign.SubmitOptions) (int, error) {
	index := -1
	for i, txn := range txns {
		if !e.IsRotatingAccount(txn.Sender.String()) {
			continue
		}
		if index >= 0 {
			return -1, fmt.Errorf("transactions %d and %d are both from rotating accounts; a group holds one rotating spend, multi-stage groups are not supported", index+1, i+1)
		}
		index = i
	}
	if index < 0 {
		return -1, nil
	}
	if index < len(opts.LsigArgsMap) && len(opts.LsigArgsMap[index]) > 0 {
		return -1, fmt.Errorf("rotating accounts take no LogicSig arguments")
	}
	for i, txn := range txns {
		if i == index {
			continue
		}
		authority := e.AuthCache.ResolveEffectiveSigner(txn.Sender.String())
		if !e.signerCacheHasAddress(authority) {
			return -1, fmt.Errorf("transaction %d: its signing key %s is not held by the signer; a rotating spend can be grouped only with transactions the same signer signs", i+1, authority)
		}
		keyType := e.signerCacheKeyType(authority)
		flow := e.signerCacheSigningFlow(authority)
		if flow == signerapi.SigningFlowRotating1 || rotatingkey.IsRotatingKeyType(keyType) {
			return -1, fmt.Errorf("transaction %d: is signed by another rotating account; a group holds one rotating spend", i+1)
		}
		if keytypes.IsCosignerKeyType(keyType) || flow == signerapi.SigningFlowCosigner1 {
			return -1, fmt.Errorf("transaction %d: guarded and witness keys cannot sign alongside a rotating spend", i+1)
		}
		if _, bounded := e.signerCacheBoundedMaxFee(authority); bounded {
			return -1, fmt.Errorf("transaction %d: bounded authorization keys cannot sign alongside a rotating spend", i+1)
		}
	}
	return index, nil
}
