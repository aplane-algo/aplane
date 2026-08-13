// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"bytes"
	"fmt"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// validateSignedGroupMutations is the client-side authority boundary for an
// ordinary /sign response. The signer may increase reported fees, assign a
// canonical group ID, and append reported canonical resource dummies. It may
// not alter any other transaction field.
func validateSignedGroupMutations(
	original []types.Transaction,
	signed []types.SignedTxn,
	signedBytes [][]byte,
	mutations *signerapi.MutationReport,
) error {
	if len(signed) != len(signedBytes) {
		return fmt.Errorf("decoded signed transaction count %d does not match wire count %d", len(signed), len(signedBytes))
	}
	if len(signed) < len(original) {
		return fmt.Errorf("signer returned %d transaction(s), want at least %d", len(signed), len(original))
	}

	appended := len(signed) - len(original)
	if mutations == nil {
		if appended != 0 {
			return fmt.Errorf("signer appended %d transaction(s) without a mutation report", appended)
		}
	} else {
		if mutations.OriginalCount != len(original) {
			return fmt.Errorf("mutation original_count %d does not match request count %d", mutations.OriginalCount, len(original))
		}
		if mutations.FinalCount != len(signed) {
			return fmt.Errorf("mutation final_count %d does not match returned count %d", mutations.FinalCount, len(signed))
		}
		if mutations.DummiesAdded != appended {
			return fmt.Errorf("mutation dummies_added %d does not match appended count %d", mutations.DummiesAdded, appended)
		}
		if mutations.PassthroughCount != 0 {
			return fmt.Errorf("ordinary /sign returned %d passthrough transaction(s) for sign-only input", mutations.PassthroughCount)
		}
		if mutations.ForeignCount != 0 {
			return fmt.Errorf("ordinary /sign returned %d foreign transaction(s) for sign-only input", mutations.ForeignCount)
		}
		if mutations.TotalFeesDelta < 0 {
			return fmt.Errorf("mutation total_fees_delta must not be negative")
		}
		if appended > 0 && !mutations.GroupIDChanged {
			return fmt.Errorf("mutation appended dummies without reporting a group ID change")
		}
		if len(signed) == 1 && mutations.GroupIDChanged {
			return fmt.Errorf("mutation reported a group ID change for a single transaction")
		}
	}

	feeModified := make(map[int]struct{})
	if mutations != nil {
		for _, index := range mutations.FeesModified {
			if index < 0 || index >= len(original) {
				return fmt.Errorf("mutation fee index %d is outside original positions", index)
			}
			if _, duplicate := feeModified[index]; duplicate {
				return fmt.Errorf("mutation fee index %d is duplicated", index)
			}
			feeModified[index] = struct{}{}
		}
	}

	var totalFeeDelta uint64
	for i := range original {
		want := original[i]
		got := signed[i].Txn
		if mutations != nil && mutations.GroupIDChanged {
			want.Group = got.Group
		}
		if _, ok := feeModified[i]; ok {
			if got.Fee <= want.Fee {
				return fmt.Errorf("reported fee mutation at original position %d did not increase the fee", i+1)
			}
			delta := uint64(got.Fee - want.Fee)
			if ^uint64(0)-totalFeeDelta < delta {
				return fmt.Errorf("observed fee delta overflows uint64")
			}
			totalFeeDelta += delta
			want.Fee = got.Fee
		}
		if !bytes.Equal(txnutil.EncodeWithPrefix(want), txnutil.EncodeWithPrefix(got)) {
			return fmt.Errorf("signer changed unreported fields at original position %d", i+1)
		}
	}
	if mutations != nil && uint64(mutations.TotalFeesDelta) != totalFeeDelta {
		return fmt.Errorf("mutation total_fees_delta %d does not match observed delta %d", mutations.TotalFeesDelta, totalFeeDelta)
	}

	finalTxns := make([]types.Transaction, len(signed))
	for i := range signed {
		finalTxns[i] = signed[i].Txn
	}
	groupID, err := validateCanonicalReturnedGroup(finalTxns)
	if err != nil {
		return err
	}
	if appended == 0 {
		return nil
	}
	return validateCanonicalReturnedDummies(original[0], groupID, signed[len(original):], signedBytes[len(original):])
}

func validateCanonicalReturnedGroup(txns []types.Transaction) (types.Digest, error) {
	if len(txns) < 2 {
		return types.Digest{}, nil
	}
	ungrouped := append([]types.Transaction(nil), txns...)
	for i := range ungrouped {
		ungrouped[i].Group = types.Digest{}
	}
	want, err := sdkcrypto.ComputeGroupID(ungrouped)
	if err != nil {
		return types.Digest{}, fmt.Errorf("compute canonical returned group ID: %w", err)
	}
	for i := range txns {
		if txns[i].Group != want {
			return types.Digest{}, fmt.Errorf("returned transaction %d does not carry the canonical group ID", i+1)
		}
	}
	return want, nil
}

func validateCanonicalReturnedDummies(
	firstOriginal types.Transaction,
	groupID types.Digest,
	returned []types.SignedTxn,
	returnedBytes [][]byte,
) error {
	params := types.SuggestedParams{
		Fee:             firstOriginal.Fee,
		FirstRoundValid: firstOriginal.FirstValid,
		LastRoundValid:  firstOriginal.LastValid,
		GenesisID:       firstOriginal.GenesisID,
		GenesisHash:     firstOriginal.GenesisHash[:],
		FlatFee:         true,
	}
	wantTxns, err := signing.CreateDummyTransactions(len(returned), params)
	if err != nil {
		return fmt.Errorf("recreate canonical resource dummies: %w", err)
	}
	for i := range wantTxns {
		wantTxns[i].Group = groupID
		if !bytes.Equal(txnutil.EncodeWithPrefix(wantTxns[i]), txnutil.EncodeWithPrefix(returned[i].Txn)) {
			return fmt.Errorf("appended transaction %d is not the canonical resource dummy", i+1)
		}
		wantSigned, signErr := signing.SignDummyTransaction(wantTxns[i])
		if signErr != nil {
			return fmt.Errorf("recreate canonical resource dummy signature %d: %w", i+1, signErr)
		}
		if !bytes.Equal(msgpack.Encode(wantSigned), returnedBytes[i]) {
			return fmt.Errorf("appended transaction %d does not carry the canonical resource dummy authorization", i+1)
		}
	}
	return nil
}
