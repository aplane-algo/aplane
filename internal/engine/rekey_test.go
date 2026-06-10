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

func TestPrepareRekey_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, _, err := eng.PrepareRekey(context.Background(), RekeyParams{From: testAddr(1), To: testAddr(2)})
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestPrepareRekey_Unrekey(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	result, checkResult, err := eng.PrepareRekey(context.Background(), RekeyParams{From: addr, To: addr})
	if err != nil {
		t.Fatalf("PrepareRekey() error = %v", err)
	}
	if !checkResult.IsUnrekey {
		t.Error("should be unrekey when From == To")
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

func TestPrepareRekey_TargetAlreadyRekeyed(t *testing.T) {
	sender := testAddr(1)
	target := testAddr(2)
	otherAuth := testAddr(3)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 1_000_000)
	transport.addAccountFull(models.Account{
		Address:    target,
		Amount:     1_000_000,
		MinBalance: 100_000,
		AuthAddr:   otherAuth, // target is rekeyed
		Status:     "Offline",
	})
	eng := setupEngineWithMockAlgod(t, transport)

	_, checkResult, err := eng.PrepareRekey(context.Background(), RekeyParams{From: sender, To: target})
	if err == nil {
		t.Fatal("expected error for target already rekeyed")
	}
	if !strings.Contains(err.Error(), "cannot rekey to") || !strings.Contains(err.Error(), "itself rekeyed") {
		t.Errorf("unexpected error: %v", err)
	}
	if checkResult == nil || !checkResult.TargetIsRekeyed {
		t.Error("should report target is rekeyed")
	}
}

func TestPrepareRekey_Success(t *testing.T) {
	sender := testAddr(1)
	target := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccount(sender, 1_000_000)
	transport.addAccount(target, 1_000_000) // not rekeyed (AuthAddr empty)
	eng := setupEngineWithMockAlgod(t, transport)

	result, checkResult, err := eng.PrepareRekey(context.Background(), RekeyParams{From: sender, To: target})
	if err != nil || result == nil {
		t.Fatalf("PrepareRekey() error = %v, result = %v", err, result)
	}
	if checkResult.IsUnrekey {
		t.Error("should not be unrekey")
	}

	txn := result.Transaction
	if txn.Type != "pay" {
		t.Errorf("txn.Type = %q, want %q (rekey uses payment)", txn.Type, "pay")
	}
	if txn.Amount != 0 {
		t.Errorf("txn.Amount = %d, want 0 for rekey", txn.Amount)
	}
	if txn.RekeyTo.IsZero() {
		t.Error("txn.RekeyTo should be set")
	}
	if txn.RekeyTo.String() != target {
		t.Errorf("txn.RekeyTo = %q, want %q", txn.RekeyTo.String(), target)
	}
}
