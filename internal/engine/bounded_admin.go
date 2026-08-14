// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// BoundedAdminPreparation is the frozen signer-approved authority fragment
// passed to an external contract-admin helper.
type BoundedAdminPreparation struct {
	Request boundedprotocol.Request
}

// PrepareExternalBoundedAdmin obtains the Falcon spending partial from the
// signer and binds it to the current network and authorization context.
func (e *Engine) PrepareExternalBoundedAdmin(ctx context.Context, prep *TransactionPrepResult) (*BoundedAdminPreparation, error) {
	if prep == nil {
		return nil, fmt.Errorf("bounded-admin transaction is required")
	}
	if e.Simulate {
		return nil, fmt.Errorf("bounded-admin operations cannot run in simulate mode")
	}
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if err := e.validateAlgodConsensus(ctx); err != nil {
		return nil, fmt.Errorf("validate algod consensus before bounded-admin signing: %w", err)
	}
	txn := prep.Transaction
	sender := txn.Sender.String()
	if _, err := e.RefreshAuthAddressWithContext(ctx, sender); err != nil {
		return nil, fmt.Errorf("refresh current authorization address: %w", err)
	}
	currentAuth := e.AuthCache.ResolveEffectiveSigner(sender)
	partial, err := e.Connection.RequestBoundedAdminWithContext(ctx, signerapi.BoundedAdminOperationRekey, []signerapi.SignRequest{{
		AuthAddress: currentAuth,
		TxnSender:   sender,
		TxnBytesHex: hex.EncodeToString(txnutil.EncodeWithPrefix(txn)),
	}})
	if err != nil {
		return nil, fmt.Errorf("prepare bounded-admin spending partial: %w", err)
	}
	request, err := boundedprotocol.NewRequest(boundedprotocol.RequestPayload{
		Partial:            *partial,
		Network:            e.GetNetwork(),
		GenesisHashHex:     hex.EncodeToString(txn.GenesisHash[:]),
		CurrentAuthAddress: currentAuth,
	})
	if err != nil {
		return nil, fmt.Errorf("validate bounded-admin signer partial: %w", err)
	}
	return &BoundedAdminPreparation{Request: request}, nil
}

// SubmitCompletedBoundedAdmin rechecks mutable chain context and submits a
// helper-validated, fully signed bounded-admin group.
func (e *Engine) SubmitCompletedBoundedAdmin(ctx context.Context, preparation *BoundedAdminPreparation, signed [][]byte, txns []types.Transaction, wait bool) (*SubmitResult, error) {
	if preparation == nil {
		return nil, fmt.Errorf("bounded-admin preparation is required")
	}
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if err := boundedprotocol.ValidateEnvelope(preparation.Request); err != nil {
		return nil, fmt.Errorf("validate bounded-admin preparation envelope: %w", err)
	}
	targetIndex := preparation.Request.Payload.Partial.TargetIndex
	if len(signed) == 0 || len(signed) != len(txns) || targetIndex < 0 || targetIndex >= len(txns) {
		return nil, fmt.Errorf("completed bounded-admin group shape is invalid")
	}
	if preparation.Request.Payload.Network != e.GetNetwork() {
		return nil, fmt.Errorf("bounded-admin network %q does not match active network %q", preparation.Request.Payload.Network, e.GetNetwork())
	}
	params, err := e.AlgodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("query genesis context before bounded-admin submission: %w", err)
	}
	if _, err := resolveSupportedConsensus(params.ConsensusVersion); err != nil {
		return nil, err
	}
	if hex.EncodeToString(params.GenesisHash) != preparation.Request.Payload.GenesisHashHex {
		return nil, fmt.Errorf("bounded-admin genesis hash does not match active network")
	}
	targetTxn := txns[targetIndex]
	currentAuth, err := e.RefreshAuthAddressWithContext(ctx, targetTxn.Sender.String())
	if err != nil {
		return nil, fmt.Errorf("refresh current authorization before submission: %w", err)
	}
	if currentAuth == "" {
		currentAuth = targetTxn.Sender.String()
	}
	if currentAuth != preparation.Request.Payload.CurrentAuthAddress {
		return nil, fmt.Errorf("current authorization address changed after bounded-admin preparation")
	}
	status, err := e.AlgodClient.Status().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("query current round before bounded-admin submission: %w", err)
	}
	if status.LastRound > uint64(targetTxn.LastValid) {
		return nil, fmt.Errorf("bounded-admin operation expired at round %d (current round %d)", targetTxn.LastValid, status.LastRound)
	}
	if status.LastRound+1 < uint64(targetTxn.FirstValid) {
		return nil, fmt.Errorf("bounded-admin operation is not valid until round %d (next round %d)", targetTxn.FirstValid, status.LastRound+1)
	}
	var output bytes.Buffer
	txIDs, err := signing.SubmitTransactionsWithContext(ctx, signed, e.AlgodClient, wait, &output)
	result := &SubmitResult{
		Transaction: targetTxn,
		Confirmed:   wait && err == nil,
		Output:      output.String(),
	}
	if targetIndex < len(txIDs) {
		result.TxID = txIDs[targetIndex]
	}
	if err != nil {
		return result, fmt.Errorf("submit bounded-admin operation: %w", err)
	}
	if targetIndex < len(txns) {
		result.Transaction = txns[targetIndex]
	}
	if result.Confirmed {
		if refreshErr := e.refreshRekeyedSenders(ctx, []types.Transaction{targetTxn}); refreshErr != nil {
			result.AuthRefreshWarning = refreshErr.Error()
		}
	}
	return result, nil
}
