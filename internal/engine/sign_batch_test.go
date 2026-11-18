// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A prepared transaction's batch label reaches /sign with it, and one without
// a label sends none.
func TestSignAndSubmitSendsThePreparedBatchLabel(t *testing.T) {
	native := testAddress(21)
	keys := []signerapi.KeyInfo{{Address: native.String(), KeyType: "ed25519"}}
	for _, batch := range []*signerapi.SignBatch{{Position: 2, Count: 3}, nil} {
		f := newLsigArgsEngine(t, keys, nil)
		prep := &TransactionPrepResult{Transaction: f.payment(t, native), Batch: batch}
		if _, err := f.eng.SignAndSubmit(context.Background(), prep, LsigArgs{}, false); err == nil {
			t.Fatal("SignAndSubmit() error = nil, want the test signer's refusal")
		}
		f.mu.Lock()
		sent := append([]*signerapi.SignBatch(nil), f.batches...)
		f.mu.Unlock()
		if len(sent) != 1 {
			t.Fatalf("batch %+v: /sign was called %d time(s), want once", batch, len(sent))
		}
		switch got := sent[0]; {
		case batch == nil && got != nil:
			t.Fatalf("an unlabeled transaction sent batch %+v", got)
		case batch != nil && (got == nil || *got != *batch):
			t.Fatalf("batch on the wire = %+v, want %+v", got, batch)
		}
	}
}
