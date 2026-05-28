// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approvalpolicy

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestCheckDecodedTxnWarnings(t *testing.T) {
	zeroAddr := types.Address{}
	nonZeroAddr := types.Address{1}

	tests := []struct {
		name      string
		txn       types.Transaction
		wantCount int
		wantField string
	}{
		{name: "clean transaction", txn: types.Transaction{}, wantCount: 0},
		{name: "RekeyTo", txn: types.Transaction{Header: types.Header{RekeyTo: nonZeroAddr}}, wantCount: 1, wantField: "RekeyTo"},
		{name: "CloseRemainderTo", txn: types.Transaction{PaymentTxnFields: types.PaymentTxnFields{CloseRemainderTo: nonZeroAddr}}, wantCount: 1, wantField: "CloseRemainderTo"},
		{name: "AssetCloseTo", txn: types.Transaction{AssetTransferTxnFields: types.AssetTransferTxnFields{AssetCloseTo: nonZeroAddr}}, wantCount: 1, wantField: "AssetCloseTo"},
		{
			name:      "clawback",
			txn:       types.Transaction{Header: types.Header{Sender: zeroAddr}, AssetTransferTxnFields: types.AssetTransferTxnFields{AssetSender: nonZeroAddr}},
			wantCount: 1,
			wantField: "AssetSender",
		},
		{name: "high fee", txn: types.Transaction{Header: types.Header{Fee: types.MicroAlgos(2_000_000)}}, wantCount: 1, wantField: "Fee"},
		{
			name:      "multiple warnings",
			txn:       types.Transaction{Header: types.Header{RekeyTo: nonZeroAddr, Fee: types.MicroAlgos(5_000_000)}, PaymentTxnFields: types.PaymentTxnFields{CloseRemainderTo: nonZeroAddr}},
			wantCount: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations := CheckDecodedTxnWarnings(tc.txn, nil)
			if len(violations) != tc.wantCount {
				t.Errorf("expected %d violations, got %d: %+v", tc.wantCount, len(violations), violations)
			}
			if tc.wantField != "" && len(violations) > 0 && violations[0].Field != tc.wantField {
				t.Errorf("expected field %q, got %q", tc.wantField, violations[0].Field)
			}
		})
	}
}

func TestCheckGroupWarnings(t *testing.T) {
	nonZeroAddr := types.Address{1}

	t.Run("sparse group with warnings on different txns", func(t *testing.T) {
		txns := []types.Transaction{
			{},
			{Header: types.Header{RekeyTo: nonZeroAddr}},
			{},
			{PaymentTxnFields: types.PaymentTxnFields{CloseRemainderTo: nonZeroAddr}},
		}

		violations := CheckGroupWarnings(txns, nil)
		if len(violations) != 2 {
			t.Fatalf("expected 2 violations, got %d: %+v", len(violations), violations)
		}
		if !strings.HasPrefix(violations[0].Field, "Tx 2/4:") {
			t.Errorf("expected 'Tx 2/4:' prefix, got %q", violations[0].Field)
		}
		if !strings.HasPrefix(violations[1].Field, "Tx 4/4:") {
			t.Errorf("expected 'Tx 4/4:' prefix, got %q", violations[1].Field)
		}
	})

	t.Run("2-txn group with RekeyTo and CloseRemainderTo", func(t *testing.T) {
		rekeyTarget := types.Address{0xAA}
		closeTarget := types.Address{0xBB}

		txns := []types.Transaction{
			{Header: types.Header{RekeyTo: rekeyTarget}},
			{PaymentTxnFields: types.PaymentTxnFields{CloseRemainderTo: closeTarget}},
		}

		violations := CheckGroupWarnings(txns, nil)
		if len(violations) != 2 {
			t.Fatalf("expected 2 violations, got %d: %+v", len(violations), violations)
		}
		if violations[0].Field != "Tx 1/2: RekeyTo" {
			t.Errorf("expected 'Tx 1/2: RekeyTo', got %q", violations[0].Field)
		}
		if violations[0].Severity != "critical" {
			t.Errorf("expected severity 'critical', got %q", violations[0].Severity)
		}
		if violations[0].Value != rekeyTarget.String() {
			t.Errorf("expected value %q, got %q", rekeyTarget.String(), violations[0].Value)
		}
		if violations[1].Field != "Tx 2/2: CloseRemainderTo" {
			t.Errorf("expected 'Tx 2/2: CloseRemainderTo', got %q", violations[1].Field)
		}
		if violations[1].Severity != "critical" {
			t.Errorf("expected severity 'critical', got %q", violations[1].Severity)
		}
		if violations[1].Value != closeTarget.String() {
			t.Errorf("expected value %q, got %q", closeTarget.String(), violations[1].Value)
		}
	})

	t.Run("clean group produces no warnings", func(t *testing.T) {
		txns := []types.Transaction{{}, {}, {}}
		violations := CheckGroupWarnings(txns, nil)
		if len(violations) != 0 {
			t.Errorf("expected 0 violations, got %d: %+v", len(violations), violations)
		}
	})
}

func TestRekeyToKnownAddress(t *testing.T) {
	rekeyTarget := types.Address{0xAA}
	txn := types.Transaction{Header: types.Header{RekeyTo: rekeyTarget}}

	t.Run("unknown target warns about losing control", func(t *testing.T) {
		violations := CheckDecodedTxnWarnings(txn, nil)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if !strings.Contains(violations[0].Message, "LOSE CONTROL") {
			t.Errorf("expected 'LOSE CONTROL' in message, got %q", violations[0].Message)
		}
	})

	t.Run("known target omits lose control warning", func(t *testing.T) {
		known := map[string]bool{rekeyTarget.String(): true}
		violations := CheckDecodedTxnWarnings(txn, known)
		if len(violations) != 1 {
			t.Fatalf("expected 1 violation, got %d", len(violations))
		}
		if strings.Contains(violations[0].Message, "LOSE CONTROL") {
			t.Errorf("should not warn about losing control for known address, got %q", violations[0].Message)
		}
	})
}
