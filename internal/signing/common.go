// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	_ "embed"
	"fmt"
	"math"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

//go:embed dummy.teal.tok
var EmbeddedDummyTealTok []byte

// AdjustLSigFeesForDummies splits dummy transaction fees evenly across all LSig transactions.
// This ensures fair fee distribution when multiple LSig accounts participate in the same group.
//
// Fee Splitting Formula:
//
//	totalDummyFees = dummyCount × minFee
//	feePerLSig = totalDummyFees ÷ lsigCount (integer division)
//	remainder = totalDummyFees % lsigCount
//
// Each LSig transaction gets feePerLSig, and the first transaction gets any remainder
// to ensure the exact total is paid (avoids rounding issues).
//
// Example with 2 LSig senders, 5 dummies, minFee=1000:
//
//	totalDummyFees = 5 × 1000 = 5000 microAlgos
//	feePerLSig = 5000 ÷ 2 = 2500 microAlgos
//	remainder = 5000 % 2 = 0 microAlgos
//	→ LSig1: 2500 + 0 = 2500, LSig2: 2500
//	→ Total: 5000 microAlgos ✓
//
// Parameters:
//
//	txns: Slice of transactions (will be modified in place)
//	lsigIndices: Indices of all LSig transactions in txns
//	dummyCount: Number of dummy transactions being added
//	minFee: Network minimum fee per transaction (from suggested params)
//	incentiveFee: Optional extra fee for first LSig (e.g., 2 ALGO for consensus eligibility)
//
// See FEE_SPLITTING.md for detailed documentation.
func AdjustLSigFeesForDummies(txns []types.Transaction, lsigIndices []int, dummyCount int, minFee uint64, incentiveFee uint64) error {
	if len(lsigIndices) == 0 {
		return fmt.Errorf("no LSig transactions to adjust fees for")
	}
	if dummyCount < 0 {
		return fmt.Errorf("dummyCount cannot be negative: %d", dummyCount)
	}

	// Validate all indices are within bounds
	for _, idx := range lsigIndices {
		if idx < 0 || idx >= len(txns) {
			return fmt.Errorf("invalid LSig transaction index: %d", idx)
		}
	}

	info, err := CalculateDummyFees(dummyCount, len(lsigIndices), minFee)
	if err != nil {
		return err
	}
	totalDummyFees := types.MicroAlgos(info.TotalFees)

	// Split evenly across all LSig transactions using integer division
	lsigCount := len(lsigIndices)
	feePerLSig := totalDummyFees / types.MicroAlgos(lsigCount)
	remainder := totalDummyFees % types.MicroAlgos(lsigCount)

	// Distribute the split fees
	for i, idx := range lsigIndices {
		updatedFee := uint64(txns[idx].Fee) + uint64(feePerLSig)
		if updatedFee < uint64(txns[idx].Fee) {
			return fmt.Errorf("LSig fee overflow at transaction index %d", idx)
		}
		txns[idx].Fee = types.MicroAlgos(updatedFee)

		// First LSig also gets any remainder from division
		// This ensures total fees exactly match (no rounding loss)
		// Example: 5000 ÷ 3 = 1666 per, remainder 2
		//   → LSig1: 1666+2, LSig2: 1666, LSig3: 1666
		//   → Total: 5000 ✓
		if i == 0 {
			updatedFee = uint64(txns[idx].Fee) + uint64(remainder)
			if updatedFee < uint64(txns[idx].Fee) {
				return fmt.Errorf("LSig remainder fee overflow at transaction index %d", idx)
			}
			txns[idx].Fee = types.MicroAlgos(updatedFee)
		}
	}

	// Add optional incentive fee to first LSig (e.g., for consensus participation)
	// This is separate from dummy fees and not split
	if incentiveFee > 0 {
		updatedFee := uint64(txns[lsigIndices[0]].Fee) + incentiveFee
		if updatedFee < uint64(txns[lsigIndices[0]].Fee) {
			return fmt.Errorf("LSig incentive fee overflow at transaction index %d", lsigIndices[0])
		}
		txns[lsigIndices[0]].Fee = types.MicroAlgos(updatedFee)
	}

	return nil
}

// DummyFeeInfo contains calculated fee information for dummy transactions.
type DummyFeeInfo struct {
	MinFee     uint64 // Network minimum fee used
	TotalFees  uint64 // Total fees for all dummies
	FeePerLSig uint64 // Approximate fee per LSig transaction
	DummyCount int    // Number of dummy transactions
	LSigCount  int    // Number of LSig transactions sharing the fees
}

// CalculateDummyFees computes the fee breakdown for dummy transactions.
// Returns fee information without modifying any transactions.
func CalculateDummyFees(dummyCount, lsigCount int, minFee uint64) (DummyFeeInfo, error) {
	if dummyCount < 0 {
		return DummyFeeInfo{}, fmt.Errorf("dummyCount cannot be negative: %d", dummyCount)
	}
	if lsigCount < 0 {
		return DummyFeeInfo{}, fmt.Errorf("lsigCount cannot be negative: %d", lsigCount)
	}
	if minFee > 0 && uint64(dummyCount) > math.MaxUint64/minFee {
		return DummyFeeInfo{}, fmt.Errorf("dummy fee total overflows uint64: dummyCount=%d minFee=%d", dummyCount, minFee)
	}

	totalFees := uint64(dummyCount) * minFee
	feePerLSig := uint64(0)
	if lsigCount > 0 {
		feePerLSig = totalFees / uint64(lsigCount)
	}
	return DummyFeeInfo{
		MinFee:     minFee,
		TotalFees:  totalFees,
		FeePerLSig: feePerLSig,
		DummyCount: dummyCount,
		LSigCount:  lsigCount,
	}, nil
}

// ApplyDummyFees distributes dummy transaction fees across LSig transactions,
// or falls back to the first transaction if no LSig indices are provided.
// Returns the fee info for logging/display purposes.
func ApplyDummyFees(txns []types.Transaction, lsigIndices []int, dummyCount int, minFee uint64) (DummyFeeInfo, error) {
	info, err := CalculateDummyFees(dummyCount, len(lsigIndices), minFee)
	if err != nil {
		return DummyFeeInfo{}, err
	}

	if len(lsigIndices) > 0 {
		// Distribute across LSig transactions
		err := AdjustLSigFeesForDummies(txns, lsigIndices, dummyCount, minFee, 0)
		if err != nil {
			return info, err
		}
	} else {
		// Fallback: put all fees on first transaction
		if len(txns) == 0 {
			return info, fmt.Errorf("no transactions to apply fees to")
		}
		updatedFee := uint64(txns[0].Fee) + info.TotalFees
		if updatedFee < uint64(txns[0].Fee) {
			return info, fmt.Errorf("dummy fee overflow at transaction index 0")
		}
		txns[0].Fee = types.MicroAlgos(updatedFee)
	}

	return info, nil
}

// DefaultMinFee is the standard Algorand minimum fee (1000 microAlgos).
const DefaultMinFee uint64 = 1000

// AssignGroupID computes a group ID for the given transactions and assigns it to all.
// All transactions must have empty group IDs before calling this function.
func AssignGroupID(txns []types.Transaction) (types.Digest, error) {
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		return types.Digest{}, fmt.Errorf("failed to compute group ID: %w", err)
	}

	for i := range txns {
		txns[i].Group = gid
	}

	return gid, nil
}
