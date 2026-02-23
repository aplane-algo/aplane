// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// testAddress creates a valid Algorand address for testing
func testAddress(index int) types.Address {
	var addr types.Address
	addr[0] = byte(index)
	addr[1] = byte(index >> 8)
	return addr
}

// TestPreparePayment_NoAlgodClient tests error when algod client is not configured
func TestPreparePayment_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	// AlgodClient is nil by default

	params := SendPaymentParams{
		From:   testAddress(1).String(),
		To:     testAddress(2).String(),
		Amount: 1000000,
	}

	_, _, err := eng.PreparePayment(params)
	if err != ErrNoAlgodClient {
		t.Errorf("Expected ErrNoAlgodClient, got %v", err)
	}
}

// TestPrepareClose_NoAlgodClient tests error when algod client is not configured
func TestPrepareClose_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	// AlgodClient is nil by default

	params := CloseAccountParams{
		From:    testAddress(1).String(),
		CloseTo: testAddress(2).String(),
	}

	_, _, err := eng.PrepareClose(params)
	if err != ErrNoAlgodClient {
		t.Errorf("Expected ErrNoAlgodClient, got %v", err)
	}
}

// TestSendPaymentParams_Defaults tests SendPaymentParams structure
func TestSendPaymentParams_Defaults(t *testing.T) {
	params := SendPaymentParams{
		From:   testAddress(1).String(),
		To:     testAddress(2).String(),
		Amount: 5000000, // 5 ALGO
	}

	// Verify defaults
	if params.Fee != 0 {
		t.Error("Default Fee should be 0")
	}
	if params.UseFlatFee != false {
		t.Error("Default UseFlatFee should be false")
	}
	if params.Close != false {
		t.Error("Default Close should be false")
	}
	if params.Note != "" {
		t.Error("Default Note should be empty")
	}
	if params.LsigArgs != nil {
		t.Error("Default LsigArgs should be nil")
	}
}

// TestCloseAccountParams_Defaults tests CloseAccountParams structure
func TestCloseAccountParams_Defaults(t *testing.T) {
	params := CloseAccountParams{
		From:    testAddress(1).String(),
		CloseTo: testAddress(2).String(),
	}

	// Verify defaults
	if params.Fee != 0 {
		t.Error("Default Fee should be 0")
	}
	if params.UseFlatFee != false {
		t.Error("Default UseFlatFee should be false")
	}
	if params.LsigArgs != nil {
		t.Error("Default LsigArgs should be nil")
	}
}

// TestCloseAccountCheckResult_Fields tests CloseAccountCheckResult structure
func TestCloseAccountCheckResult_Fields(t *testing.T) {
	result := &CloseAccountCheckResult{
		Balance:      1000000,
		IsOnline:     false,
		HasASAs:      true,
		ASACount:     3,
		ASAIDs:       []uint64{12345, 67890, 11111},
		CloseToValid: true,
	}

	if result.Balance != 1000000 {
		t.Errorf("Balance = %d, want 1000000", result.Balance)
	}

	if result.IsOnline != false {
		t.Error("IsOnline should be false")
	}

	if result.HasASAs != true {
		t.Error("HasASAs should be true")
	}

	if result.ASACount != 3 {
		t.Errorf("ASACount = %d, want 3", result.ASACount)
	}

	if len(result.ASAIDs) != 3 {
		t.Errorf("len(ASAIDs) = %d, want 3", len(result.ASAIDs))
	}

	if result.CloseToValid != true {
		t.Error("CloseToValid should be true")
	}
}

// TestBalanceCheckResult_Fields tests BalanceCheckResult structure
func TestBalanceCheckResult_Fields(t *testing.T) {
	result := &BalanceCheckResult{
		SenderBalance:    10.5,
		RequiredAmount:   2.001,
		SufficientFunds:  true,
		NewAccount:       false,
		ReceiverOptedIn:  true,
		MinBalance:       100000,
		RemainingBalance: 8499000,
		BelowMinBalance:  false,
	}

	if result.SenderBalance != 10.5 {
		t.Errorf("SenderBalance = %f, want 10.5", result.SenderBalance)
	}

	if result.RequiredAmount != 2.001 {
		t.Errorf("RequiredAmount = %f, want 2.001", result.RequiredAmount)
	}

	if !result.SufficientFunds {
		t.Error("SufficientFunds should be true")
	}

	if result.NewAccount {
		t.Error("NewAccount should be false")
	}

	if !result.ReceiverOptedIn {
		t.Error("ReceiverOptedIn should be true")
	}

	if result.BelowMinBalance {
		t.Error("BelowMinBalance should be false")
	}
}

// TestTransactionPrepResult_Fields tests TransactionPrepResult structure
func TestTransactionPrepResult_Fields(t *testing.T) {
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: testAddress(1),
			Fee:    types.MicroAlgos(1000),
		},
	}

	ctx := &SigningContext{
		Address:     testAddress(1).String(),
		SigningAddr: testAddress(1).String(),
		KeyType:     "ed25519",
	}

	result := &TransactionPrepResult{
		Transaction:    txn,
		SigningContext: ctx,
		AmountInUnits:  1000000,
	}

	if result.Transaction.Type != types.PaymentTx {
		t.Errorf("Transaction.Type = %v, want PaymentTx", result.Transaction.Type)
	}

	if result.SigningContext.Address != testAddress(1).String() {
		t.Error("SigningContext.Address not set correctly")
	}

	if result.AmountInUnits != 1000000 {
		t.Errorf("AmountInUnits = %d, want 1000000", result.AmountInUnits)
	}
}

// TestSendPaymentParams_WithNote tests note field
func TestSendPaymentParams_WithNote(t *testing.T) {
	params := SendPaymentParams{
		From:   testAddress(1).String(),
		To:     testAddress(2).String(),
		Amount: 1000000,
		Note:   "Test payment for services",
	}

	if params.Note != "Test payment for services" {
		t.Errorf("Note = %q, want 'Test payment for services'", params.Note)
	}
}

// TestSendPaymentParams_WithFlatFee tests flat fee settings
func TestSendPaymentParams_WithFlatFee(t *testing.T) {
	params := SendPaymentParams{
		From:       testAddress(1).String(),
		To:         testAddress(2).String(),
		Amount:     1000000,
		Fee:        2000,
		UseFlatFee: true,
	}

	if params.Fee != 2000 {
		t.Errorf("Fee = %d, want 2000", params.Fee)
	}

	if !params.UseFlatFee {
		t.Error("UseFlatFee should be true")
	}
}

// TestSendPaymentParams_WithClose tests close flag
func TestSendPaymentParams_WithClose(t *testing.T) {
	params := SendPaymentParams{
		From:   testAddress(1).String(),
		To:     testAddress(2).String(),
		Amount: 0,
		Close:  true,
	}

	if !params.Close {
		t.Error("Close should be true")
	}
}

// TestSendPaymentParams_WithLsigArgs tests LogicSig arguments
func TestSendPaymentParams_WithLsigArgs(t *testing.T) {
	params := SendPaymentParams{
		From:   testAddress(1).String(),
		To:     testAddress(2).String(),
		Amount: 1000000,
		LsigArgs: map[string][]byte{
			"preimage": []byte("secret"),
		},
	}

	if params.LsigArgs == nil {
		t.Fatal("LsigArgs should not be nil")
	}

	if string(params.LsigArgs["preimage"]) != "secret" {
		t.Errorf("LsigArgs[preimage] = %q, want 'secret'", params.LsigArgs["preimage"])
	}
}

// TestSigningContext_Creation tests SigningContext structure
func TestSigningContext_Creation(t *testing.T) {
	sender := testAddress(1).String()
	authAddr := testAddress(2).String()

	ctx := &SigningContext{
		Address:     sender,
		SigningAddr: authAddr,
		KeyType:     "ed25519",
	}

	if ctx.Address != sender {
		t.Errorf("Address = %s, want %s", ctx.Address, sender)
	}

	if ctx.SigningAddr != authAddr {
		t.Errorf("SigningAddr = %s, want %s", ctx.SigningAddr, authAddr)
	}

	if ctx.KeyType != "ed25519" {
		t.Errorf("KeyType = %s, want ed25519", ctx.KeyType)
	}
}

// TestSigningContext_SameSigningAddr tests non-rekeyed account context
func TestSigningContext_SameSigningAddr(t *testing.T) {
	sender := testAddress(1).String()

	ctx := &SigningContext{
		Address:     sender,
		SigningAddr: sender, // Same as sender (not rekeyed)
		KeyType:     "ed25519",
	}

	if ctx.Address != ctx.SigningAddr {
		t.Error("Address and SigningAddr should match for non-rekeyed")
	}
}

// TestBalanceCheckResult_InsufficientFunds tests insufficient funds scenario
func TestBalanceCheckResult_InsufficientFunds(t *testing.T) {
	result := &BalanceCheckResult{
		SenderBalance:   0.5,   // Only 0.5 ALGO
		RequiredAmount:  2.001, // Need 2.001 ALGO
		SufficientFunds: false,
	}

	if result.SufficientFunds {
		t.Error("SufficientFunds should be false when balance < required")
	}

	if result.SenderBalance >= result.RequiredAmount {
		t.Error("SenderBalance should be less than RequiredAmount")
	}
}

// TestBalanceCheckResult_NewAccount tests new account scenario
func TestBalanceCheckResult_NewAccount(t *testing.T) {
	result := &BalanceCheckResult{
		SenderBalance:   10.0,
		RequiredAmount:  1.001,
		SufficientFunds: true,
		NewAccount:      true,
		ReceiverOptedIn: true, // Always true for ALGO
	}

	if !result.NewAccount {
		t.Error("NewAccount should be true for account with zero balance")
	}
}

// TestBalanceCheckResult_BelowMinBalance tests min balance check
func TestBalanceCheckResult_BelowMinBalance(t *testing.T) {
	result := &BalanceCheckResult{
		SenderBalance:    0.15,
		RequiredAmount:   0.101,
		SufficientFunds:  true,
		MinBalance:       100000, // 0.1 ALGO
		RemainingBalance: 49000,  // 0.049 ALGO - below min
		BelowMinBalance:  true,
	}

	if !result.BelowMinBalance {
		t.Error("BelowMinBalance should be true when remaining < min")
	}
}
