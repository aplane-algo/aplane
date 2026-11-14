// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"bytes"
	"encoding/hex"
	"fmt"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
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
// group the signer returned for originalCount sign-only positions: the counts
// validateReportCounts checks, and then that the report claims no passthrough
// or foreign positions and reports a group ID change whenever it appended
// dummies. endpoint names the response in the passthrough and foreign errors.
// The fields of each position are ValidateOriginalPositions' to check.
func validateMutationReportCounts(endpoint string, originalCount, returnedCount int, mutations *signerapi.MutationReport) error {
	if err := validateReportCounts(originalCount, returnedCount, mutations); err != nil {
		return err
	}
	if mutations == nil {
		return nil
	}
	appended := returnedCount - originalCount
	if mutations.PassthroughCount != 0 {
		return fmt.Errorf("%s returned %d passthrough transaction(s) for sign-only input", endpoint, mutations.PassthroughCount)
	}
	if mutations.ForeignCount != 0 {
		return fmt.Errorf("%s returned %d foreign transaction(s) for sign-only input", endpoint, mutations.ForeignCount)
	}
	if appended > 0 && !mutations.GroupIDChanged {
		return fmt.Errorf("mutation appended dummies without reporting a group ID change")
	}
	return nil
}

// validateReportCounts checks the counts of a mutation report against a group
// the signer returned for originalCount positions: the group keeps every
// original, the signer may append transactions only with a report, and the
// report must count the request, the returned group and the appended dummies.
// A report may not claim a group ID change for a single transaction: the
// signer assigns a group ID only to two or more, and keeps a single
// transaction's as it was sent, none or its own.
func validateReportCounts(originalCount, returnedCount int, mutations *signerapi.MutationReport) error {
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
	if returnedCount == 1 && mutations.GroupIDChanged {
		return fmt.Errorf("mutation reported a group ID change for a single transaction")
	}
	return nil
}

// DecodePlannedGroup decodes the transactions of a /plan answer. Each must be
// the TX-prefixed canonical encoding of what it decodes to: bytes that decode
// leniently could differ from the group the signer froze. Its errors name a
// transaction by its zero-based index and wrap the canonical decoder's.
func DecodePlannedGroup(transactions []string) ([]types.Transaction, error) {
	planned := make([]types.Transaction, len(transactions))
	for i, txnHex := range transactions {
		raw, err := hex.DecodeString(txnHex)
		if err != nil {
			return nil, fmt.Errorf("planned transaction at index %d: invalid hex: %w", i, err)
		}
		txn, err := canonical.DecodeTXPrefixed(raw)
		if err != nil {
			return nil, fmt.Errorf("planned transaction at index %d: %w", i, err)
		}
		planned[i] = txn
	}
	return planned, nil
}

// ValidateGroupPlan checks a group the signer planned, decoded canonically,
// against the transactions the client sent for it: the mutation report's
// counts, each original position (ValidateOriginalPositions: only the group ID
// and the fee raises the report lists may differ), the group ID over the final
// group, and the canonical resource dummies appended after the originals. The
// group ID rules follow the planner. A single transaction keeps the group ID
// it was sent with, so a report of a change to it is refused. A changed group
// ID on originals that all carry one is refused unless the report also lists
// a fee raise or appended dummies. The presign-plan flow, the cosigned flow
// and JS plan() check their /plan answer with it. Its errors name a position
// by its zero-based index; an original position changed beyond what the
// report allows is an *UnreportedChangeError.
func ValidateGroupPlan(original, planned []types.Transaction, mutations *signerapi.MutationReport) error {
	if err := validateReportCounts(len(original), len(planned), mutations); err != nil {
		return err
	}
	if err := ValidateOriginalPositions(original, planned, mutations); err != nil {
		return err
	}
	if mutations != nil && mutations.GroupIDChanged && len(original) > 0 &&
		len(planned) == len(original) && len(mutations.FeesModified) == 0 {
		var zero types.Digest
		requiresAssignment := false
		for i := range original {
			requiresAssignment = requiresAssignment || original[i].Group == zero
		}
		if !requiresAssignment {
			return fmt.Errorf("signer changed an existing group ID without a fee or membership mutation")
		}
	}
	groupID, err := ValidateCanonicalGroupID(planned)
	if err != nil {
		return err
	}
	appended := len(planned) - len(original)
	if appended == 0 {
		return nil
	}
	// A dummy is rebuilt from the first original transaction.
	if len(original) == 0 {
		return fmt.Errorf("signer appended %d transaction(s) to an empty group", appended)
	}
	_, err = ValidateCanonicalDummyTxns(original[0], groupID, planned, len(original))
	return err
}

// ValidateUnsignedFees refuses a planned group that changed the fee of an
// original position the signer does not sign. The signer's planner raises
// fees only on the positions it signs: a foreign or passthrough position is
// never a fee target, and the authorization cost a foreign position declares
// (lsig_resources, pq_scheme) is charged to the signer's own positions. So
// the fee of such a position must come back as the client sent it, whether or
// not the report lists it; the fees are compared directly. unsigned maps the
// zero-based index of each such position to the name its error gives it.
// Run it after ValidateGroupPlan, which leaves a reported fee raise as the
// only change it can find.
func ValidateUnsignedFees(original, planned []types.Transaction, unsigned map[int]string) error {
	if len(planned) < len(original) {
		return fmt.Errorf("signer returned %d transaction(s), want at least %d", len(planned), len(original))
	}
	for i := range original {
		kind, ok := unsigned[i]
		if !ok || planned[i].Fee == original[i].Fee {
			continue
		}
		return fmt.Errorf("plan changed the fee of %s slot at index %d from %d to %d microAlgos; the signer may raise fees only on the slots it signs",
			kind, i, original[i].Fee, planned[i].Fee)
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
// *UnreportedChangeError. The ordinary /sign response, the rotating prepare
// and the /plan answers ValidateGroupPlan checks all run this one check. Its
// errors name a position
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
