// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Pregrouped-signed plugin submission: a plugin hands APlane a complete,
// already-signed, already-grouped Algorand atomic group; APlane validates that
// the group is self-consistent and submits the exact signed bytes verbatim.
//
// This path is for fully plugin-owned/foreign-signed groups (e.g. a Mithras
// spend). apsigner is NOT involved: no /plan, /sign, group assignment, fee
// adjustment, dummy insertion, regrouping, or reordering. The bytes submitted
// are exactly the bytes the plugin produced.

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signing"
)

// PregroupedSignedGroup is a decoded, validated, ready-to-submit pregrouped-signed
// group. It binds the decoded transactions to their original signed bytes, so the
// bytes submitted are always exactly the bytes that were validated. The fields are
// unexported and DecodePregroupedSigned is the only constructor, so a caller can
// never pair a validated group with unrelated submission bytes.
type PregroupedSignedGroup struct {
	stxns []types.SignedTxn
	raw   [][]byte
}

// Transactions returns the decoded transactions for display/inspection only.
// Submission never re-derives bytes from these; it uses the original signed bytes
// bound at decode time.
func (g *PregroupedSignedGroup) Transactions() []types.SignedTxn {
	if g == nil {
		return nil
	}
	return g.stxns
}

// DecodePregroupedSigned decodes base64 signed-transaction intents and applies the
// immutability gate. It is the only way to construct a PregroupedSignedGroup, so a
// submittable group is always validated and its bytes always match its
// transactions.
func DecodePregroupedSigned(encoded []string) (*PregroupedSignedGroup, error) {
	stxns, raw, err := decodeSignedTxnIntents(encoded)
	if err != nil {
		return nil, err
	}
	if err := validatePregroupedSigned(stxns); err != nil {
		return nil, err
	}
	return &PregroupedSignedGroup{stxns: stxns, raw: raw}, nil
}

// decodeSignedTxnIntents decodes base64 signed-transaction blobs, returning the
// decoded SignedTxn objects (for validation and simulation) and the original raw
// bytes in order (for verbatim submission). The raw bytes are preserved
// deliberately: the contract is byte-preservation, so submission never re-encodes
// what the plugin signed.
func decodeSignedTxnIntents(encoded []string) ([]types.SignedTxn, [][]byte, error) {
	if len(encoded) == 0 {
		return nil, nil, fmt.Errorf("pregrouped-signed: no transactions")
	}
	stxns := make([]types.SignedTxn, len(encoded))
	rawBytes := make([][]byte, len(encoded))
	for i, enc := range encoded {
		if enc == "" {
			return nil, nil, fmt.Errorf("transaction %d: missing encoded data", i+1)
		}
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return nil, nil, fmt.Errorf("transaction %d: failed to decode base64: %w", i+1, err)
		}
		var st types.SignedTxn
		if err := msgpack.Decode(raw, &st); err != nil {
			return nil, nil, fmt.Errorf("transaction %d: failed to decode signed transaction msgpack: %w", i+1, err)
		}
		stxns[i] = st
		rawBytes[i] = raw
	}
	return stxns, rawBytes, nil
}

// validatePregroupedSigned is the immutability gate. It proves the supplied group
// is self-consistent and complete WITHOUT rewriting anything that will be
// submitted: every slot must carry the same non-zero group ID, and that group ID
// must equal the ID recomputed over the transactions themselves. A mismatch means
// the group was tampered with, reordered, or is incomplete (a subset) — it is
// rejected, never "fixed".
//
// It does not and cannot judge intent: a self-consistent group can still be
// malicious. That is the job of the client-side local review, which is mandatory
// for this mode precisely because no signer-side policy/approval participates.
func validatePregroupedSigned(stxns []types.SignedTxn) error {
	if len(stxns) == 0 {
		return fmt.Errorf("pregrouped-signed: empty group")
	}
	// A single transaction is not an atomic group; a lone txn carrying a group ID
	// is more likely malformed than intentional. Require a real group.
	if len(stxns) < 2 {
		return fmt.Errorf("pregrouped-signed: group must contain at least 2 transactions, got %d", len(stxns))
	}
	if len(stxns) > types.MaxTxGroupSize {
		return fmt.Errorf("pregrouped-signed: group size %d exceeds max %d", len(stxns), types.MaxTxGroupSize)
	}

	group := stxns[0].Txn.Group
	if group == (types.Digest{}) {
		return fmt.Errorf("pregrouped-signed: transaction 1 has no group ID")
	}
	for i, st := range stxns {
		if st.Txn.Group == (types.Digest{}) {
			return fmt.Errorf("pregrouped-signed: transaction %d has no group ID", i+1)
		}
		if st.Txn.Group != group {
			return fmt.Errorf("pregrouped-signed: transaction %d group ID differs from transaction 1", i+1)
		}
	}

	// Recompute the expected group ID over bare copies (Group cleared) — this is
	// how Algorand derives the group ID — and compare to the embedded value.
	bare := make([]types.Transaction, len(stxns))
	for i, st := range stxns {
		bare[i] = st.Txn
		bare[i].Group = types.Digest{}
	}
	computed, err := crypto.ComputeGroupID(bare)
	if err != nil {
		return fmt.Errorf("pregrouped-signed: failed to recompute group ID: %w", err)
	}
	if computed != group {
		return fmt.Errorf("pregrouped-signed: embedded group ID does not match the transactions (tampered, reordered, or incomplete group)")
	}
	return nil
}

// SubmitPregroupedSigned submits (or simulates) a validated pregrouped-signed
// group verbatim. The submit path passes the original signed bytes through
// unchanged; only the simulate path uses the decoded objects (it does not
// broadcast, so re-encoding there is harmless).
//
// This path requires only an algod client — NOT a signer connection — because no
// APlane-managed key participates.
func (e *Engine) SubmitPregroupedSigned(ctx context.Context, g *PregroupedSignedGroup) (*PluginSubmitResult, error) {
	if g == nil || len(g.raw) == 0 {
		return nil, fmt.Errorf("pregrouped-signed: nil or empty group")
	}
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}
	if err := e.validateAlgodConsensus(ctx); err != nil {
		return nil, fmt.Errorf("validate algod consensus before pregrouped submission: %w", err)
	}

	if e.Simulate {
		var output bytes.Buffer
		txIDs, err := signing.SimulateSignedTransactionsWithContext(ctx, g.stxns, e.AlgodClient, &output)
		return &PluginSubmitResult{TxIDs: txIDs, Output: output.String()}, errorWithSubmissionOutput(err, output.String())
	}

	var output bytes.Buffer
	txIDs, err := signing.SubmitTransactionsWithContext(ctx, g.raw, e.AlgodClient, true, &output)
	return &PluginSubmitResult{TxIDs: txIDs, Output: output.String()}, errorWithSubmissionOutput(err, output.String())
}
