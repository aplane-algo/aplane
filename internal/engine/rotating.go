// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/clientsign"
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

// rotatingSender reports whether txns is a rotating account's spend. A
// rotating account signs alone: its spend is the only transaction the client
// may send, because the signer forms the group around it.
func (e *Engine) rotatingSender(txns []types.Transaction, opts clientsign.SubmitOptions) (bool, error) {
	found := false
	for _, txn := range txns {
		if e.IsRotatingAccount(txn.Sender.String()) {
			found = true
		}
	}
	if !found {
		return false, nil
	}
	if len(txns) != 1 {
		return false, fmt.Errorf("a rotating account's transaction must be sent alone; it cannot be grouped with other transactions")
	}
	if len(opts.LsigArgsMap) > 0 && len(opts.LsigArgsMap[0]) > 0 {
		return false, fmt.Errorf("rotating accounts take no LogicSig arguments")
	}
	return true, nil
}
