// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"
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
	if result.Incentive != nil {
		t.Errorf("offline registration carries an incentive decision: %+v", *result.Incentive)
	}
}

// onlineKeyReg is an online registration for addr with well-formed keys.
func onlineKeyReg(addr string, eligible bool) KeyRegParams {
	key32 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	key64 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	return KeyRegParams{
		Account:           addr,
		Mode:              "online",
		VoteKey:           key32,
		SelectionKey:      key32,
		StateProofKey:     key64,
		VoteFirst:         1,
		VoteLast:          100,
		KeyDilution:       10,
		IncentiveEligible: eligible,
	}
}

// The 2 ALGO fee is paid only to become eligible: an account that is
// eligible already keeps its eligibility through the registration at the
// ordinary fee. Eligibility is read only when it is asked for, and what the
// read found is on the result.
func TestPrepareKeyReg_IncentiveFee(t *testing.T) {
	tests := []struct {
		name            string
		alreadyEligible bool
		requested       bool
		wantFee         uint64
	}{
		{"requested, not eligible yet", false, true, 2_000_000},
		{"requested, eligible already", true, true, 1000},
		{"not requested, eligible already", true, false, 1000},
		{"not requested, not eligible", false, false, 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := testAddr(1)
			transport := newAccountMockTransport(t)
			transport.txParams.Fee = 0 // the ordinary fee is the minimum fee
			transport.addAccountFull(models.Account{
				Address: addr, Amount: 10_000_000, MinBalance: 100_000, Status: "Online",
				IncentiveEligible: tt.alreadyEligible,
			})
			eng := setupEngineWithMockAlgod(t, transport)

			result, err := eng.PrepareKeyReg(context.Background(), onlineKeyReg(addr, tt.requested))
			if err != nil {
				t.Fatalf("PrepareKeyReg() error = %v", err)
			}
			if uint64(result.Transaction.Fee) != tt.wantFee {
				t.Errorf("txn.Fee = %d, want %d", result.Transaction.Fee, tt.wantFee)
			}
			switch {
			case !tt.requested && result.Incentive != nil:
				t.Errorf("Incentive = %+v for a registration that did not ask for eligibility", *result.Incentive)
			case tt.requested && (result.Incentive == nil || result.Incentive.AlreadyEligible != tt.alreadyEligible):
				t.Errorf("Incentive = %+v, want AlreadyEligible %v", result.Incentive, tt.alreadyEligible)
			}
		})
	}
}

// A request for eligibility whose read fails is refused, so it neither pays
// a fee that may not be owed nor drops the request. Without a request there
// is no read, so algod failing to answer for the account changes nothing.
func TestPrepareKeyReg_EligibilityThatCannotBeRead(t *testing.T) {
	for _, requested := range []bool{true, false} {
		addr := testAddr(1)
		transport := newAccountMockTransport(t)
		transport.txParams.Fee = 0
		transport.addAccount(addr, 10_000_000)
		eng := setupEngineWithMockAlgod(t, transport)
		// The account signs for itself, so building the signing context asks
		// algod nothing; then algod stops answering for the account.
		eng.AuthCache.AuthAddresses[addr] = ""
		delete(transport.accounts, addr)

		result, err := eng.PrepareKeyReg(context.Background(), onlineKeyReg(addr, requested))
		if requested {
			if err == nil || !strings.Contains(err.Error(), "failed to query incentive eligibility") {
				t.Errorf("requested: PrepareKeyReg() error = %v, want the eligibility lookup error", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("not requested: PrepareKeyReg() error = %v, want no read and no error", err)
		}
		if uint64(result.Transaction.Fee) != 1000 || result.Incentive != nil {
			t.Errorf("not requested: fee = %d, incentive = %+v; want the ordinary fee and no decision",
				result.Transaction.Fee, result.Incentive)
		}
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

func TestPrepareKeyReg_OnlineRequiresKeyDilution(t *testing.T) {
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
		VoteFirst:     1,
		VoteLast:      100,
	})
	if err == nil || !strings.Contains(err.Error(), "keydilution") {
		t.Fatalf("online keyreg without a key dilution: %v, want a keydilution error", err)
	}
}

func TestPrepareKeyReg_OfflineRefusesIncentiveEligibility(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 5_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	_, err := eng.PrepareKeyReg(context.Background(), KeyRegParams{
		Account: addr, Mode: "offline", IncentiveEligible: true,
	})
	if err == nil || !strings.Contains(err.Error(), "eligible applies only when going online") {
		t.Fatalf("offline keyreg with eligible: %v, want it refused", err)
	}
}

// The zero address in a rekey or close field is the same as leaving the field
// out, so the transaction would do neither and be reported as having done it.
func TestZeroAddressIsRefusedAsARekeyOrCloseTarget(t *testing.T) {
	addr := testAddr(1)
	zero := types.Address{}.String()
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 5_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	if _, _, err := eng.PrepareRekey(context.Background(), RekeyParams{From: addr, To: zero}); err == nil ||
		!strings.Contains(err.Error(), "zero address") {
		t.Errorf("rekey to the zero address: %v, want it refused", err)
	}
	if _, _, err := eng.PrepareClose(context.Background(), CloseAccountParams{From: addr, CloseTo: zero}); err == nil ||
		!strings.Contains(err.Error(), "zero address") {
		t.Errorf("close to the zero address: %v, want it refused", err)
	}
	if _, _, err := eng.PrepareOptOut(context.Background(), OptOutParams{Account: addr, AssetID: 5, CloseTo: zero}); err == nil ||
		!strings.Contains(err.Error(), "zero address") {
		t.Errorf("asset close to the zero address: %v, want it refused", err)
	}
}
