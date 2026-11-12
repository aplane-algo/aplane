// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"bytes"
	"fmt"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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
	if err := validateMutationReportCounts("ordinary /sign", len(original), len(signed), mutations); err != nil {
		return err
	}
	appended := len(signed) - len(original)

	finalTxns := make([]types.Transaction, len(signed))
	for i := range signed {
		finalTxns[i] = signed[i].Txn
	}
	if err := ValidateOriginalPositions(original, finalTxns, mutations); err != nil {
		return err
	}
	groupID, err := ValidateCanonicalGroupID(finalTxns)
	if err != nil {
		return err
	}
	if appended == 0 {
		return nil
	}
	return validateCanonicalReturnedDummies(original[0], groupID, signed, signedBytes, len(original))
}

// validateMutationReportCounts checks the counts of a mutation report against a
// group the signer returned for originalCount sign-only positions: it may
// append transactions only with a report, which must count the request, the
// returned group and the appended dummies, claim no passthrough or foreign
// positions, and report a group ID change exactly when the group needs one.
// endpoint names the response in the passthrough and foreign errors. The
// fields of each position are ValidateOriginalPositions' to check.
func validateMutationReportCounts(endpoint string, originalCount, returnedCount int, mutations *signerapi.MutationReport) error {
	if returnedCount < originalCount {
		return fmt.Errorf("signer returned %d transaction(s), want at least %d", returnedCount, originalCount)
	}
	appended := returnedCount - originalCount
	if mutations == nil {
		if appended != 0 {
			return fmt.Errorf("signer appended %d transaction(s) without a mutation report", appended)
		}
		return nil
	}
	if mutations.OriginalCount != originalCount {
		return fmt.Errorf("mutation original_count %d does not match request count %d", mutations.OriginalCount, originalCount)
	}
	if mutations.FinalCount != returnedCount {
		return fmt.Errorf("mutation final_count %d does not match returned count %d", mutations.FinalCount, returnedCount)
	}
	if mutations.DummiesAdded != appended {
		return fmt.Errorf("mutation dummies_added %d does not match appended count %d", mutations.DummiesAdded, appended)
	}
	if mutations.PassthroughCount != 0 {
		return fmt.Errorf("%s returned %d passthrough transaction(s) for sign-only input", endpoint, mutations.PassthroughCount)
	}
	if mutations.ForeignCount != 0 {
		return fmt.Errorf("%s returned %d foreign transaction(s) for sign-only input", endpoint, mutations.ForeignCount)
	}
	if appended > 0 && !mutations.GroupIDChanged {
		return fmt.Errorf("mutation appended dummies without reporting a group ID change")
	}
	if returnedCount == 1 && mutations.GroupIDChanged {
		return fmt.Errorf("mutation reported a group ID change for a single transaction")
	}
	return nil
}

// UnreportedChangeError is an original position of a planned or signed group
// that differs from the transaction the client sent by more than the signer
// may change.
type UnreportedChangeError struct {
	// Index is the zero-based original position.
	Index int
}

func (e *UnreportedChangeError) Error() string {
	return fmt.Sprintf("signer changed unreported fields at original index %d", e.Index)
}

// ValidateOriginalPositions checks the original positions of a group the
// signer planned or signed against the transactions the client sent. A
// position may differ only in its group ID, when the report says the group ID
// changed, and in a fee the report lists, which must have risen. The rises
// must sum, without overflowing, to the report's total_fees_delta, which must
// not be negative. A position that differs in anything else is an
// *UnreportedChangeError. The ordinary /sign response, the cosigned /plan and
// the plugin presign /plan all run this one check. Its errors name a position
// by its zero-based index, as the report's fee indices do and as every check
// of a response in this package does.
func ValidateOriginalPositions(original, returned []types.Transaction, mutations *signerapi.MutationReport) error {
	if len(returned) < len(original) {
		return fmt.Errorf("signer returned %d transaction(s), want at least %d", len(returned), len(original))
	}
	feeModified := make(map[int]struct{})
	if mutations != nil {
		if mutations.TotalFeesDelta < 0 {
			return fmt.Errorf("mutation total_fees_delta must not be negative")
		}
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
		got := returned[i]
		if mutations != nil && mutations.GroupIDChanged {
			want.Group = got.Group
		}
		if _, ok := feeModified[i]; ok {
			if got.Fee <= want.Fee {
				return fmt.Errorf("reported fee mutation at original index %d did not increase the fee", i)
			}
			delta := uint64(got.Fee - want.Fee)
			if ^uint64(0)-totalFeeDelta < delta {
				return fmt.Errorf("observed fee delta overflows uint64")
			}
			totalFeeDelta += delta
			want.Fee = got.Fee
		}
		if !bytes.Equal(txnutil.EncodeWithPrefix(want), txnutil.EncodeWithPrefix(got)) {
			return &UnreportedChangeError{Index: i}
		}
	}
	if mutations != nil && uint64(mutations.TotalFeesDelta) != totalFeeDelta {
		return fmt.Errorf("mutation total_fees_delta %d does not match observed delta %d", mutations.TotalFeesDelta, totalFeeDelta)
	}
	return nil
}

// ValidateCanonicalGroupID checks that every transaction of a multi-transaction
// group carries the group ID computed over the group itself, and returns it. A
// single transaction needs no group ID; the zero digest is returned. Its error
// names a transaction by its zero-based index in the group.
func ValidateCanonicalGroupID(txns []types.Transaction) (types.Digest, error) {
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
			return types.Digest{}, fmt.Errorf("returned transaction at index %d does not carry the canonical group ID", i)
		}
	}
	return want, nil
}

// validateCanonicalReturnedDummies checks the signed transactions after the
// first originalCount: each must be a canonical resource dummy, signed with
// the canonical dummy authorization.
func validateCanonicalReturnedDummies(
	firstOriginal types.Transaction,
	groupID types.Digest,
	returned []types.SignedTxn,
	returnedBytes [][]byte,
	originalCount int,
) error {
	returnedTxns := make([]types.Transaction, len(returned))
	for i := range returned {
		returnedTxns[i] = returned[i].Txn
	}
	wantTxns, err := ValidateCanonicalDummyTxns(firstOriginal, groupID, returnedTxns, originalCount)
	if err != nil {
		return err
	}
	for i := range wantTxns {
		index := originalCount + i
		wantSigned, signErr := signing.SignDummyTransaction(wantTxns[i])
		if signErr != nil {
			return fmt.Errorf("recreate canonical resource dummy signature at index %d: %w", index, signErr)
		}
		if !bytes.Equal(msgpack.Encode(wantSigned), returnedBytes[index]) {
			return fmt.Errorf("appended transaction at index %d does not carry the canonical resource dummy authorization", index)
		}
	}
	return nil
}

// ValidateCanonicalDummyTxns checks that the transactions of group after its
// first originalCount, the appended ones, are exactly the canonical resource
// dummies the signer's planner builds for this group: zero fee self-payments
// from the dummy address with notes 0..n-1, the first original transaction's
// validity window and genesis, and the group's ID. It returns the recreated
// dummies. Its error names a dummy by its zero-based index in the group.
func ValidateCanonicalDummyTxns(
	firstOriginal types.Transaction,
	groupID types.Digest,
	group []types.Transaction,
	originalCount int,
) ([]types.Transaction, error) {
	if originalCount < 0 || originalCount > len(group) {
		return nil, fmt.Errorf("group has %d transaction(s), fewer than its %d original(s)", len(group), originalCount)
	}
	appended := group[originalCount:]
	params := types.SuggestedParams{
		Fee:             firstOriginal.Fee,
		FirstRoundValid: firstOriginal.FirstValid,
		LastRoundValid:  firstOriginal.LastValid,
		GenesisID:       firstOriginal.GenesisID,
		GenesisHash:     firstOriginal.GenesisHash[:],
		FlatFee:         true,
	}
	wantTxns, err := signing.CreateDummyTransactions(len(appended), params)
	if err != nil {
		return nil, fmt.Errorf("recreate canonical resource dummies: %w", err)
	}
	for i := range wantTxns {
		wantTxns[i].Group = groupID
		if !bytes.Equal(txnutil.EncodeWithPrefix(wantTxns[i]), txnutil.EncodeWithPrefix(appended[i])) {
			return nil, fmt.Errorf("appended transaction at index %d is not the canonical resource dummy", originalCount+i)
		}
	}
	return wantTxns, nil
}
