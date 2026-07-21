// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txeffects_test

import (
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

func TestWarningAndLintConsumersObserveManifestDangerFields(t *testing.T) {
	target := types.Address{2}
	tests := []struct {
		name         string
		effect       txeffects.EffectKind
		warningField string
		txn          types.Transaction
		config       *policy.Config
	}{
		{
			name: "rekey", effect: txeffects.EffectRekey, warningField: "RekeyTo",
			txn:    types.Transaction{Header: types.Header{RekeyTo: target}},
			config: &policy.Config{RejectForeignRekey: true},
		},
		{
			name: "close", effect: txeffects.EffectClose, warningField: "CloseRemainderTo",
			txn:    types.Transaction{PaymentTxnFields: types.PaymentTxnFields{CloseRemainderTo: target}},
			config: &policy.Config{RejectCloseRemainder: true},
		},
		{
			name: "asset close", effect: txeffects.EffectAssetClose, warningField: "AssetCloseTo",
			txn:    types.Transaction{AssetTransferTxnFields: types.AssetTransferTxnFields{AssetCloseTo: target}},
			config: &policy.Config{RejectAssetClose: true},
		},
		{
			name: "clawback", effect: txeffects.EffectClawback, warningField: "AssetSender",
			txn:    types.Transaction{AssetTransferTxnFields: types.AssetTransferTxnFields{AssetSender: target}},
			config: &policy.Config{RejectClawback: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !txeffects.Inspect(tt.txn).Has(tt.effect) {
				t.Fatalf("txeffects did not observe %q", tt.effect)
			}
			warnings := approvalpolicy.CheckDecodedTxnWarnings(tt.txn, nil)
			if len(warnings) != 1 || warnings[0].Field != tt.warningField {
				t.Fatalf("warnings = %#v, want one %s warning", warnings, tt.warningField)
			}
			lints := policy.CheckTxnPolicyLintsWithKnownAddresses(tt.txn, tt.txn.Sender.String(), tt.config, nil)
			if len(lints) != 1 {
				t.Fatalf("lints = %#v, want one violation", lints)
			}
		})
	}
}

func TestPolicyClawbackExceptionCannotWeakenBoundedClassification(t *testing.T) {
	sender := types.Address{1}
	txn := types.Transaction{
		Type:                   types.AssetTransferTx,
		Header:                 types.Header{Sender: sender},
		AssetTransferTxnFields: types.AssetTransferTxnFields{AssetSender: sender},
	}

	classification := txeffects.Classify(txn)
	if !classification.Facts.Has(txeffects.EffectClawback) || classification.Shape != txeffects.ShapeDeniedEffect {
		t.Fatalf("classification = %+v, want conservative clawback denial", classification)
	}
	if warnings := approvalpolicy.CheckDecodedTxnWarnings(txn, nil); len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want policy-specific same-sender exception", warnings)
	}
	if lints := policy.CheckTxnPolicyLints(txn, txn.Sender.String(), &policy.Config{RejectClawback: true}); len(lints) != 0 {
		t.Fatalf("lints = %#v, want policy-specific same-sender exception", lints)
	}
}
