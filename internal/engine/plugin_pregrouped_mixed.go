// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Pregrouped-mixed: the plugin supplies a complete, immutable atomic group (final
// group ID already set on every slot) mixing already-plugin-signed passthrough
// slots and unsigned APlane-managed slots. APlane validates the group is
// self-consistent and has apsigner sign only the managed slots over the fixed group
// ID — no /plan, no canonicalization. Works only when the managed key needs no
// extra in-group budget (ed25519); a Falcon managed key would need budget txns the
// immutable group cannot carry, and should use presign-plan instead.

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
)

// PregroupedMixedSlot is one slot of an immutable mixed group. A managed slot is
// unsigned and signed by apsigner; a passthrough slot carries the plugin's signed
// bytes verbatim. Txn is the underlying transaction either way (for a passthrough
// slot, the transaction embedded in the signed bytes).
type PregroupedMixedSlot struct {
	Managed   bool
	Txn       types.Transaction
	SignedRaw []byte // passthrough slots only: the original signed transaction bytes
}

// SignAndSubmitPregroupedMixed validates an immutable mixed group and submits it,
// with apsigner signing the managed slots over the plugin-set group ID.
func (e *Engine) SignAndSubmitPregroupedMixed(ctx context.Context, slots []PregroupedMixedSlot, lsigArgs []map[string][]byte) (*PluginSubmitResult, error) {
	if err := validatePregroupedMixed(slots); err != nil {
		return nil, err
	}

	// An immutable group cannot carry the in-group budget transactions a managed
	// signer like Falcon needs, so reject such managed slots up front (use
	// presign-plan) instead of producing a group that fails at submit.
	if err := e.EnsureSignerCache(ctx); err != nil {
		return nil, fmt.Errorf("pregrouped-mixed: %w", err)
	}
	for i, s := range slots {
		if s.Managed {
			if size := e.signerLsigSize(s.Txn.Sender.String()); size > 0 {
				return nil, fmt.Errorf("pregrouped-mixed: managed slot %d signer needs in-group opcode budget (lsig size %d); use presign-plan instead", i+1, size)
			}
		}
	}

	signRequests := make([]signerapi.SignRequest, len(slots))
	for i, s := range slots {
		if s.Managed {
			signRequests[i] = e.managedSignRequest(s.Txn, lsigArgsAt(lsigArgs, i))
		} else {
			signRequests[i] = signerapi.SignRequest{SignedTxnHex: hex.EncodeToString(s.SignedRaw)}
		}
	}

	if e.Simulate {
		simResp, err := e.RequestGroupSimulateWithContext(ctx, signRequests)
		if err != nil {
			return nil, fmt.Errorf("server simulation failed: %w", err)
		}
		if simResp.Failed {
			return &PluginSubmitResult{TxIDs: simResp.TxIDs, Output: simResp.Output}, errorWithSubmissionOutput(signing.ErrSimulationFailed, simResp.Output)
		}
		return &PluginSubmitResult{TxIDs: simResp.TxIDs, Output: simResp.Output}, nil
	}

	signResp, err := e.RequestGroupSignWithContext(ctx, signRequests)
	if err != nil {
		return nil, fmt.Errorf("server signing failed: %w", err)
	}
	finalSignedTxns, err := decodeGroupSignResponse(signResp.Signed, len(signRequests))
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	txIDs, err := signing.SubmitTransactionsWithContext(ctx, finalSignedTxns, e.AlgodClient, true, &output)
	return &PluginSubmitResult{TxIDs: txIDs, Output: output.String()}, errorWithSubmissionOutput(err, output.String())
}

// signerLsigSize returns the LSig opcode-budget size of the key that signs for the
// given address (0 for ed25519 or an unknown key). A nonzero size means the signer
// needs in-group budget transactions, which an immutable group cannot carry.
func (e *Engine) signerLsigSize(address string) int {
	authAddr, authExists := e.AuthCache.GetAuthAddress(address)
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	if e.SignerCache.LsigSizes != nil {
		if size, ok := e.SignerCache.LsigSizes[address]; ok {
			return size
		}
		if authExists && authAddr != "" {
			if size, ok := e.SignerCache.LsigSizes[authAddr]; ok {
				return size
			}
		}
	}
	return 0
}

// validatePregroupedMixed is the immutability gate for a mixed group: every slot
// must carry the same non-zero group ID, that ID must equal the ID recomputed over
// the transactions, there must be at least one managed slot, and passthrough slots
// must carry signed bytes. The group is never rewritten.
func validatePregroupedMixed(slots []PregroupedMixedSlot) error {
	if len(slots) < 2 {
		return fmt.Errorf("pregrouped-mixed: group must contain at least 2 transactions, got %d", len(slots))
	}
	if len(slots) > types.MaxTxGroupSize {
		return fmt.Errorf("pregrouped-mixed: group size %d exceeds max %d", len(slots), types.MaxTxGroupSize)
	}

	group := slots[0].Txn.Group
	if group == (types.Digest{}) {
		return fmt.Errorf("pregrouped-mixed: transaction 1 has no group ID")
	}
	managed, passthrough := 0, 0
	for i, s := range slots {
		if s.Txn.Group == (types.Digest{}) {
			return fmt.Errorf("pregrouped-mixed: transaction %d has no group ID", i+1)
		}
		if s.Txn.Group != group {
			return fmt.Errorf("pregrouped-mixed: transaction %d group ID differs from transaction 1", i+1)
		}
		if s.Managed {
			managed++
		} else {
			passthrough++
			if len(s.SignedRaw) == 0 {
				return fmt.Errorf("pregrouped-mixed: passthrough transaction %d has no signed bytes", i+1)
			}
		}
	}
	if managed == 0 {
		return fmt.Errorf("pregrouped-mixed: requires at least one APlane-managed slot; use pregrouped-signed for an all-plugin group")
	}
	if passthrough == 0 {
		return fmt.Errorf("pregrouped-mixed: requires at least one plugin-signed passthrough slot; use the raw transaction path for an all-managed group")
	}

	bare := make([]types.Transaction, len(slots))
	for i, s := range slots {
		bare[i] = s.Txn
		bare[i].Group = types.Digest{}
	}
	computed, err := crypto.ComputeGroupID(bare)
	if err != nil {
		return fmt.Errorf("pregrouped-mixed: failed to recompute group ID: %w", err)
	}
	if computed != group {
		return fmt.Errorf("pregrouped-mixed: embedded group ID does not match the transactions (tampered, reordered, or incomplete group)")
	}
	return nil
}
