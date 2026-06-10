// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
)

func TestPrepareKeyReg_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, err := eng.PrepareKeyReg(context.Background(), KeyRegParams{Account: testAddr(1), Mode: "online"})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareKeyReg_OnlineMissingParams(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, err := eng.PrepareKeyReg(context.Background(), KeyRegParams{
		Account: addr,
		Mode:    "online",
		// Missing VoteKey, SelectionKey, StateProofKey
	})
	if err == nil {
		t.Fatal("expected error for missing online params")
	}
	if !strings.Contains(err.Error(), "votekey, selkey, sproofkey") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareKeyReg_OnlineInvalidVoteRange(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, err := eng.PrepareKeyReg(context.Background(), KeyRegParams{
		Account:       addr,
		Mode:          "online",
		VoteKey:       "dGVzdA==",
		SelectionKey:  "dGVzdA==",
		StateProofKey: "dGVzdA==",
		VoteFirst:     100,
		VoteLast:      50, // invalid: last < first
	})
	if err == nil {
		t.Fatal("expected error for invalid vote range")
	}
	if !strings.Contains(err.Error(), "votelast must be greater") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareKeyReg_OnlineZeroVoteFirst(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, err := eng.PrepareKeyReg(context.Background(), KeyRegParams{
		Account:       addr,
		Mode:          "online",
		VoteKey:       "dGVzdA==",
		SelectionKey:  "dGVzdA==",
		StateProofKey: "dGVzdA==",
		VoteFirst:     0, // invalid
		VoteLast:      100,
	})
	if err == nil {
		t.Fatal("expected error for zero votefirst")
	}
	if !strings.Contains(err.Error(), "votefirst and votelast must be > 0") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrepareKeyReg_OfflineSuccess(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.PrepareKeyReg(context.Background(), KeyRegParams{
		Account: addr,
		Mode:    "offline",
	})
	if err != nil || result == nil {
		t.Fatalf("PrepareKeyReg() error = %v, result = %v", err, result)
	}
	txn := result.Transaction
	if txn.Type != "keyreg" {
		t.Errorf("txn.Type = %q, want %q", txn.Type, "keyreg")
	}
	if txn.Sender.String() != addr {
		t.Errorf("txn.Sender = %q, want %q", txn.Sender.String(), addr)
	}
}

func TestPrepareKeyReg_IncentiveFee(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 10_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, err := eng.PrepareKeyReg(context.Background(), KeyRegParams{
		Account:           addr,
		Mode:              "offline",
		IncentiveEligible: true,
	})
	if err != nil {
		t.Fatalf("PrepareKeyReg() error = %v", err)
	}
	if uint64(result.Transaction.Fee) != 2_000_000 {
		t.Errorf("txn.Fee = %d, want 2000000 for incentive eligibility", result.Transaction.Fee)
	}
}

func TestGetIncentiveEligibility(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:           addr,
		Amount:            1_000_000,
		MinBalance:        100_000,
		Status:            "Online",
		IncentiveEligible: true,
	})
	eng := setupEngineWithMockAlgod(t, transport)

	eligible, err := eng.GetIncentiveEligibility(context.Background(), addr)
	if err != nil {
		t.Fatalf("GetIncentiveEligibility() error = %v", err)
	}
	if !eligible {
		t.Error("expected eligible = true")
	}
}
