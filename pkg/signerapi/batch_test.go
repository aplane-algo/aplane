// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"strings"
	"testing"
)

// Each request that can put a prompt to an operator takes a batch label, and
// refuses one that names no place in a batch.
func TestSignBatchLabelIsCheckedOnEveryPromptingRequest(t *testing.T) {
	requests := map[string]func(*SignBatch) error{
		"sign": func(b *SignBatch) error {
			return GroupSignRequest{Requests: []SignRequest{{AuthAddress: "ADDR", TxnBytesHex: "5458aa"}}, Batch: b}.Validate()
		},
		"component": func(b *SignBatch) error {
			return ComponentRequest{
				GroupBytesHex: []string{"5458aa"},
				Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindBase, AuthAddress: "BOUNDED"}},
				Batch:         b,
			}.Validate()
		},
		"rotating": func(b *SignBatch) error {
			return RotatingSignRequest{Account: "ACCOUNT", Transactions: []string{"5458aa"}, Batch: b}.Validate()
		},
	}
	for name, validate := range requests {
		for _, b := range []*SignBatch{nil, {Position: 1, Count: 1}, {Position: 2, Count: 3}, {Position: 3, Count: 3}, {Position: maxSignBatchCount, Count: maxSignBatchCount}} {
			if err := validate(b); err != nil {
				t.Errorf("%s: batch %+v: error = %v, want it accepted", name, b, err)
			}
		}
		for _, tc := range []struct {
			batch SignBatch
			want  string
		}{
			{SignBatch{Position: 0, Count: 3}, "batch position"},
			{SignBatch{Position: 4, Count: 3}, "batch position"},
			{SignBatch{Position: -1, Count: 3}, "batch position"},
			{SignBatch{Position: 1, Count: 0}, "batch count"},
			{SignBatch{Position: 1, Count: maxSignBatchCount + 1}, "batch count"},
		} {
			b := tc.batch
			if err := validate(&b); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: batch %+v: error = %v, want %q", name, b, err, tc.want)
			}
		}
	}
}

// The signer reads a component request through its sign request form, so the
// label has to survive the conversion.
func TestComponentRequestKeepsItsBatchLabel(t *testing.T) {
	batch := &SignBatch{Position: 2, Count: 5}
	req := ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets:       []ComponentTarget{{TargetIndex: 0, Kind: ComponentTargetKindBase, AuthAddress: "BOUNDED"}},
		Batch:         batch,
	}
	if got := req.GroupSignRequest().Batch; got != batch {
		t.Fatalf("GroupSignRequest().Batch = %+v, want %+v", got, batch)
	}
}
