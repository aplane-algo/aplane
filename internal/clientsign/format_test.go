// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestFormatTransactionSummary_AppCall(t *testing.T) {
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}

	txn := types.Transaction{
		Type: types.ApplicationCallTx,
		Header: types.Header{
			Sender: sender,
		},
		ApplicationFields: types.ApplicationFields{
			ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID:   123,
				OnCompletion:    types.OptInOC,
				ApplicationArgs: [][]byte{{0x01}, {0x02}},
			},
		},
	}

	summary := FormatTransactionSummary(txn, nil)
	for _, want := range []string{
		"App 123",
		"OptIn",
		"2 arg(s)",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q: %s", want, summary)
		}
	}
}

// A payment summary formats microAlgos exactly: a float64 loses the last
// microAlgo of an amount this large.
func TestFormatTransactionSummary_PaymentIsExact(t *testing.T) {
	txn := types.Transaction{
		Type:             types.PaymentTx,
		PaymentTxnFields: types.PaymentTxnFields{Amount: 9_007_199_254_740_993},
	}
	if summary := FormatTransactionSummary(txn, nil); !strings.HasSuffix(summary, "(9007199254.740993 ALGO)") {
		t.Fatalf("summary = %q, want the exact amount", summary)
	}
}
