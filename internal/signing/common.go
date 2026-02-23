// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package signing

import (
	_ "embed"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/util"
)

//go:embed dummy.teal.tok
var EmbeddedDummyTealTok []byte

// FormatTransactionSummary creates a human-readable summary of a transaction
// If aliasCache is nil, uses short address format. If provided, shows aliases.
func FormatTransactionSummary(txn types.Transaction, aliasCache *util.AliasCache) string {
	sender := txn.Sender.String()
	senderFmt := formatAddress(sender, aliasCache)

	switch txn.Type {
	case types.PaymentTx:
		receiver := txn.Receiver.String()
		receiverFmt := formatAddress(receiver, aliasCache)
		amount := float64(txn.Amount) / 1000000.0
		return fmt.Sprintf("Payment: %s → %s (%.6f ALGO)",
			senderFmt, receiverFmt, amount)

	case types.AssetTransferTx:
		receiver := txn.AssetReceiver.String()
		receiverFmt := formatAddress(receiver, aliasCache)
		return fmt.Sprintf("Asset Transfer: %s → %s (Asset %d, Amount %d)",
			senderFmt, receiverFmt, txn.XferAsset, txn.AssetAmount)

	case types.AssetConfigTx:
		if txn.ConfigAsset == 0 {
			return fmt.Sprintf("Asset Create: %s (creating new asset)", senderFmt)
		}
		return fmt.Sprintf("Asset Config: %s (modifying asset %d)", senderFmt, txn.ConfigAsset)

	case types.AssetFreezeTx:
		target := txn.FreezeAccount.String()
		targetFmt := formatAddress(target, aliasCache)
		return fmt.Sprintf("Asset Freeze: %s (asset %d, target %s)",
			senderFmt, txn.FreezeAsset, targetFmt)

	case types.ApplicationCallTx:
		return fmt.Sprintf("App Call: %s → App %d", senderFmt, txn.ApplicationID)

	case types.KeyRegistrationTx:
		// Check if vote key is empty (all zeros)
		emptyVotePK := true
		for _, b := range txn.VotePK {
			if b != 0 {
				emptyVotePK = false
				break
			}
		}
		if emptyVotePK {
			return fmt.Sprintf("Key Registration: %s (offline)", senderFmt)
		}
		return fmt.Sprintf("Key Registration: %s (online)", senderFmt)

	default:
		return fmt.Sprintf("Transaction: %s (type %s)", senderFmt, txn.Type)
	}
}

// formatAddress formats an address with alias if available, otherwise shortened.
// Uses util.FormatAddressWithAlias for the canonical implementation.
func formatAddress(addr string, aliasCache *util.AliasCache) string {
	return util.FormatAddressWithAlias(addr, aliasCache)
}

// CreateDummyTransactions creates the specified number of dummy self-payment transactions
// using the embedded dummy LogicSig program. All dummies have fee=0 (first Falcon txn pays).
func CreateDummyTransactions(count int, sp types.SuggestedParams) ([]types.Transaction, error) {
	if count == 0 {
		return nil, nil
	}

	// Use embedded dummy LogicSig
	dummyLSig := types.LogicSig{Logic: EmbeddedDummyTealTok, Args: nil}
	lsigAcct := crypto.LogicSigAccount{Lsig: dummyLSig}
	dummyAddr, err := lsigAcct.Address()
	if err != nil {
		return nil, fmt.Errorf("failed to compute dummy address: %w", err)
	}

	dummyTxns := make([]types.Transaction, count)

	for i := 0; i < count; i++ {
		// Create self-payment with unique note
		txn, err := transaction.MakePaymentTxn(
			dummyAddr.String(),
			dummyAddr.String(),
			0,
			[]byte{byte(i)}, // Unique note for each dummy
			"",
			sp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create dummy transaction %d: %w", i+1, err)
		}

		// CRITICAL: Set fee to 0 (first Falcon transaction pays for all)
		txn.Fee = 0

		dummyTxns[i] = txn
	}

	return dummyTxns, nil
}

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

	// Validate all indices are within bounds
	for _, idx := range lsigIndices {
		if idx < 0 || idx >= len(txns) {
			return fmt.Errorf("invalid LSig transaction index: %d", idx)
		}
	}

	// Calculate total fees needed for all dummy transactions
	// #nosec G115 - dummyCount and lsigCount are small transaction counts, safe conversion
	totalDummyFees := types.MicroAlgos(dummyCount) * types.MicroAlgos(minFee)

	// Split evenly across all LSig transactions using integer division
	lsigCount := len(lsigIndices)
	feePerLSig := totalDummyFees / types.MicroAlgos(lsigCount) // #nosec G115 - lsigCount is small
	remainder := totalDummyFees % types.MicroAlgos(lsigCount)  // #nosec G115 - lsigCount is small

	// Distribute the split fees
	for i, idx := range lsigIndices {
		// Each LSig gets their even share
		txns[idx].Fee += feePerLSig

		// First LSig also gets any remainder from division
		// This ensures total fees exactly match (no rounding loss)
		// Example: 5000 ÷ 3 = 1666 per, remainder 2
		//   → LSig1: 1666+2, LSig2: 1666, LSig3: 1666
		//   → Total: 5000 ✓
		if i == 0 {
			txns[idx].Fee += remainder
		}
	}

	// Add optional incentive fee to first LSig (e.g., for consensus participation)
	// This is separate from dummy fees and not split
	if incentiveFee > 0 {
		txns[lsigIndices[0]].Fee += types.MicroAlgos(incentiveFee)
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
func CalculateDummyFees(dummyCount, lsigCount int, minFee uint64) DummyFeeInfo {
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
	}
}

// ApplyDummyFees distributes dummy transaction fees across LSig transactions,
// or falls back to the first transaction if no LSig indices are provided.
// Returns the fee info for logging/display purposes.
func ApplyDummyFees(txns []types.Transaction, lsigIndices []int, dummyCount int, minFee uint64) (DummyFeeInfo, error) {
	info := CalculateDummyFees(dummyCount, len(lsigIndices), minFee)

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
		txns[0].Fee += types.MicroAlgos(info.TotalFees)
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
