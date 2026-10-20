// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approvalpolicy

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
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
			name:      "app delete",
			txn:       types.Transaction{Type: types.ApplicationCallTx, ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{OnCompletion: types.DeleteApplicationOC}}},
			wantCount: 1,
			wantField: "OnCompletion",
		},
		{
			name:      "app clear state",
			txn:       types.Transaction{Type: types.ApplicationCallTx, ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{OnCompletion: types.ClearStateOC}}},
			wantCount: 1,
			wantField: "OnCompletion",
		},
		{
			name:      "app noop is not flagged",
			txn:       types.Transaction{Type: types.ApplicationCallTx, ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{OnCompletion: types.NoOpOC}}},
			wantCount: 0,
		},
		{
			name:      "app update",
			txn:       types.Transaction{Type: types.ApplicationCallTx, ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{ApplicationID: 7, OnCompletion: types.UpdateApplicationOC}}},
			wantCount: 1,
			wantField: "OnCompletion",
		},
		{
			name:      "asset create is not flagged",
			txn:       types.Transaction{Type: types.AssetConfigTx, AssetConfigTxnFields: types.AssetConfigTxnFields{AssetParams: types.AssetParams{Total: 1, Manager: nonZeroAddr}}},
			wantCount: 0,
		},
		{
			name:      "asset reconfigure",
			txn:       types.Transaction{Type: types.AssetConfigTx, AssetConfigTxnFields: types.AssetConfigTxnFields{ConfigAsset: 31566704, AssetParams: types.AssetParams{Manager: nonZeroAddr}}},
			wantCount: 1,
			wantField: "ConfigAsset",
		},
		{
			name:      "asset destroy",
			txn:       types.Transaction{Type: types.AssetConfigTx, AssetConfigTxnFields: types.AssetConfigTxnFields{ConfigAsset: 31566704}},
			wantCount: 1,
			wantField: "ConfigAsset",
		},
		{
			name:      "asset freeze",
			txn:       types.Transaction{Type: types.AssetFreezeTx, AssetFreezeTxnFields: types.AssetFreezeTxnFields{FreezeAccount: nonZeroAddr, FreezeAsset: 31566704, AssetFrozen: true}},
			wantCount: 1,
			wantField: "FreezeAccount",
		},
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

// The reconfigure warning names every role address so the operator sees which
// roles the transaction keeps, moves, or clears for good.
func TestAssetReconfigureWarningNamesRoles(t *testing.T) {
	manager := types.Address{1}
	txn := types.Transaction{Type: types.AssetConfigTx, AssetConfigTxnFields: types.AssetConfigTxnFields{
		ConfigAsset: 42, AssetParams: types.AssetParams{Manager: manager},
	}}
	violations := CheckDecodedTxnWarnings(txn, nil)
	if len(violations) != 1 || violations[0].Severity != signerapproval.ViolationSeverityWarning {
		t.Fatalf("violations = %+v, want one warning", violations)
	}
	msg := violations[0].Message
	for _, want := range []string{"asset #42", "Manager: " + manager.String(), "Reserve: (cleared)", "Freeze: (cleared)", "Clawback: (cleared)"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
	destroy := CheckDecodedTxnWarnings(types.Transaction{Type: types.AssetConfigTx, AssetConfigTxnFields: types.AssetConfigTxnFields{ConfigAsset: 42}}, nil)
	if len(destroy) != 1 || destroy[0].Severity != signerapproval.ViolationSeverityCritical || !strings.Contains(destroy[0].Message, "DESTROY asset #42") {
		t.Fatalf("destroy violations = %+v, want one critical destroy warning", destroy)
	}
	unfreeze := CheckDecodedTxnWarnings(types.Transaction{Type: types.AssetFreezeTx, AssetFreezeTxnFields: types.AssetFreezeTxnFields{FreezeAccount: manager, FreezeAsset: 42}}, nil)
	if len(unfreeze) != 1 || !strings.Contains(unfreeze[0].Message, "UNFREEZE") || unfreeze[0].Value != manager.String() {
		t.Fatalf("unfreeze violations = %+v", unfreeze)
	}
}

// A rekey the signer issued itself as part of a signing protocol (a rotating
// account's next stage) is the protocol working, not a dangerous field: it
// produces no finding at all, while every other field and every other rekey
// target is reported as before.
func TestProtocolRekeyTargetIsNotAFinding(t *testing.T) {
	nextStage := types.Address{0xAB}
	other := types.Address{0xAC}
	ctx := Context{
		KnownAddresses:       map[string]bool{nextStage.String(): true},
		ProtocolRekeyTargets: map[string]bool{nextStage.String(): true},
	}

	t.Run("protocol rekey produces no finding", func(t *testing.T) {
		txn := types.Transaction{Header: types.Header{RekeyTo: nextStage}}
		if v := CheckDecodedTxnWarningsIn(txn, ctx); len(v) != 0 {
			t.Fatalf("expected no findings, got %+v", v)
		}
		if v := CheckGroupWarningsIn([]types.Transaction{txn}, ctx); len(v) != 0 {
			t.Fatalf("expected no group findings, got %+v", v)
		}
	})

	t.Run("other fields on the same transaction still warn", func(t *testing.T) {
		txn := types.Transaction{
			Type:   types.AssetTransferTx,
			Header: types.Header{RekeyTo: nextStage},
			AssetTransferTxnFields: types.AssetTransferTxnFields{
				AssetCloseTo: types.Address{0xAD},
			},
		}
		v := CheckDecodedTxnWarningsIn(txn, ctx)
		if len(v) != 1 || v[0].Field != "AssetCloseTo" {
			t.Fatalf("expected only the asset close finding, got %+v", v)
		}
	})

	t.Run("a rekey to any other address still warns", func(t *testing.T) {
		txn := types.Transaction{Header: types.Header{RekeyTo: other}}
		v := CheckDecodedTxnWarningsIn(txn, ctx)
		if len(v) != 1 || v[0].Field != "RekeyTo" || !strings.Contains(v[0].Message, "LOSE CONTROL") {
			t.Fatalf("expected the lose-control rekey finding, got %+v", v)
		}
	})

	t.Run("the two-argument form never exempts a rekey", func(t *testing.T) {
		txn := types.Transaction{Header: types.Header{RekeyTo: nextStage}}
		if v := CheckDecodedTxnWarnings(txn, ctx.KnownAddresses); len(v) != 1 {
			t.Fatalf("expected the held-address rekey finding, got %+v", v)
		}
	})
}
