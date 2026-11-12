// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// checkActiveNetwork is the network precondition of the engine's paths that
// send transactions to the signer or to algod: the active algod runs a
// reviewed consensus contract, and each transaction is for the network that
// algod serves. The signer refuses a genesis hash it does not recognize, but
// one it recognizes for another network would be signed under that network's
// policy and then sent to this algod, whose operator would hold a transaction
// valid on the other network. A transaction apshell builds takes its genesis
// from this algod; plugin drafts, plugin-signed groups, transaction files and
// JS plan() requests carry their own, so each is compared here: the genesis
// hash always, the genesis ID when the transaction sets one.
//
// It runs in checkReadyToSign, before every /sign route (ordinary, rotating
// and cosigned: built-in commands, the default plugin mode, sign files and JS
// sign()); in SignAndSubmitWithPluginSigners, on the presign-plan draft before
// its plan requests are built (its /plan request then goes to the signer
// connection directly, and its later /sign carries the checked plan); in
// RequestGroupPlanWithContext, on the decoded requests before /plan, for JS
// plan(); and in SubmitPregroupedSigned, before a plugin-signed group goes to
// algod.
//
// It reads algod at most once, reusing a read from the last
// consensusValidationReuseWindow (see activeAlgodNetwork). That read is kept
// per algod client, so an algod whose URL is pointed at another network inside
// that window passes on the network it served when it was read.
func (e *Core) checkActiveNetwork(ctx context.Context, txns []types.Transaction) error {
	network, err := e.activeAlgodNetwork(ctx)
	if err != nil {
		return fmt.Errorf("validate algod consensus: %w", err)
	}
	if len(network.genesisHash) != len(types.Digest{}) {
		return fmt.Errorf("algod reported a genesis hash of %d bytes, want %d", len(network.genesisHash), len(types.Digest{}))
	}
	for i, txn := range txns {
		if !bytes.Equal(txn.GenesisHash[:], network.genesisHash) {
			return fmt.Errorf("transaction at index %d is for another network: genesis hash %s, the active algod's is %s",
				i, describeGenesisHash(txn.GenesisHash[:]), describeGenesisHash(network.genesisHash))
		}
		if txn.GenesisID != "" && txn.GenesisID != network.genesisID {
			return fmt.Errorf("transaction at index %d is for another network: genesis ID %q, the active algod's is %q",
				i, txn.GenesisID, network.genesisID)
		}
	}
	return nil
}

// planRequestTransactions decodes the transaction each /plan request carries,
// for checkActiveNetwork: the TX-prefixed bytes of a sign or foreign entry, or
// the transaction inside a passthrough entry's signed bytes. Bytes that are not
// a canonical encoding are refused here, as the signer would refuse them.
func planRequestTransactions(requests []signerapi.SignRequest) ([]types.Transaction, error) {
	txns := make([]types.Transaction, len(requests))
	for i, request := range requests {
		encoded, signed := request.TxnBytesHex, false
		if request.SignedTxnHex != "" {
			encoded, signed = request.SignedTxnHex, true
		}
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("plan request at index %d: invalid hex: %w", i, err)
		}
		if signed {
			stxn, err := clientsign.DecodeSignedTxnToSubmit(raw)
			if err != nil {
				return nil, fmt.Errorf("plan request at index %d: signed transaction: %w", i, err)
			}
			txns[i] = stxn.Txn
			continue
		}
		txn, err := canonical.DecodeTXPrefixed(raw)
		if err != nil {
			return nil, fmt.Errorf("plan request at index %d: %w", i, err)
		}
		txns[i] = txn
	}
	return txns, nil
}

// describeGenesisHash names a genesis hash in base64, with its network when
// it is one of the known networks.
func describeGenesisHash(hash []byte) string {
	encoded := base64.StdEncoding.EncodeToString(hash)
	if network, ok := config.DefaultGenesisHashNetworkResolver().NetworkForGenesisHashBytes(hash); ok {
		return fmt.Sprintf("%s (%s)", encoded, network)
	}
	return encoded
}
