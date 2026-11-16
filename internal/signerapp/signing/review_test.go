// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/termsafe"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The review says, as data, how the request treats each transaction and what
// planning did, and the description is that review printed.
func TestBuildReviewCarriesPositionsAndChanges(t *testing.T) {
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: "AUTH1"}, {AuthAddress: "AUTH2"}, {TxnBytesHex: "aa"}, {TxnBytesHex: "bb"},
	}}
	plan := &PlanResult{
		DummiesNeeded:      1,
		FeeInfo:            DummyFeeInfo{TotalFees: 2000, FeeIndices: []int{0}},
		PassthroughIndices: map[int]bool{},
		ForeignIndices:     map[int]bool{2: true, 3: true},
		HasForeign:         true,
		HeldForeign:        map[int]*heldPosition{3: {SenderHeld: true}},
	}
	txns := make([]types.Transaction, 5)
	for i := range txns {
		txns[i].Type = types.PaymentTx
	}

	review := buildReview(req, plan, txns, describeAs("txn\n  From: A"))
	if !review.Group || len(review.Items) != 4 {
		t.Fatalf("group = %t with %d items, want a group of the 4 requested transactions", review.Group, len(review.Items))
	}
	for i, want := range []txnreview.Position{
		txnreview.PositionSign, txnreview.PositionSign, txnreview.PositionForeign, txnreview.PositionHeld,
	} {
		if got := review.Items[i].Position; got != want {
			t.Errorf("transaction %d: position %q, want %q", i+1, got, want)
		}
	}
	if note := review.Items[1].Notes; len(note) != 1 || note[0].Label != "Signing key" || note[0].Value != "AUTH2" {
		t.Errorf("transaction 2 notes = %+v", note)
	}
	if review.Items[0].Label != "" || review.Items[2].Label == "" || review.Items[3].Label == "" {
		t.Errorf("only a transaction this request does not sign has a heading label: %+v", review.Items)
	}
	changes := review.Changes
	if changes.Frozen || changes.Dummies != 1 || changes.FeeAdded != 2000 || changes.Heading != "[MODIFIED BY SERVER]" {
		t.Errorf("changes = %+v", changes)
	}
	if len(review.Banners) != 1 || !strings.HasPrefix(review.Banners[0], "[MULTI-PARTY: 2 to sign") {
		t.Errorf("banners = %q", review.Banners)
	}

	description, _, _ := BuildApprovalDescription(req, plan, txns, describeAs("txn\n  From: A"))
	if description != termsafe.Lines(review.Text()) {
		t.Errorf("the description is not the review printed:\n%s\n---\n%s", description, review.Text())
	}
	// Every part of the review is in the text.
	for _, part := range append(append([]string{changes.Heading}, changes.Lines...), review.Banners...) {
		if !strings.Contains(description, part) {
			t.Errorf("description lacks %q:\n%s", part, description)
		}
	}
	for i, item := range review.Items {
		for _, note := range item.Notes {
			if !strings.Contains(description, note.Line()+"\n") {
				t.Errorf("description lacks transaction %d's note %q", i+1, note.Line())
			}
		}
	}
}

// A request checked as sent is marked frozen, and a lone transaction is not a
// group.
func TestBuildReviewOfAFrozenSingleTransaction(t *testing.T) {
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTH"}}}
	plan := &PlanResult{Frozen: true, PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{}}
	review := buildReview(req, plan, []types.Transaction{{Type: types.PaymentTx}}, describeAs("txn"))
	if review.Group || !review.Changes.Frozen || len(review.Banners) != 0 {
		t.Fatalf("review = %+v", review)
	}
	if !strings.HasPrefix(review.Text(), "=== SINGLE TRANSACTION ===\n\n[FROZEN TRANSACTION: ") {
		t.Fatalf("text:\n%s", review.Text())
	}
}

// A bounded rekey's authorization and a rotation are fields of the
// transaction they belong to, after its own.
func TestBuildReviewAddsBoundedAndRotationFields(t *testing.T) {
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTH"}}}
	plan := &PlanResult{
		PassthroughIndices: map[int]bool{}, ForeignIndices: map[int]bool{},
		BoundedItems: []*boundedPlanItem{{Path: boundedPathListedRekey}},
		Rotating:     &rotatingPlanItem{Stage: 4, Target: 5},
	}
	review := buildReview(req, plan, []types.Transaction{{Type: types.PaymentTx}}, describeAs("txn\n  From: A"))
	var labels []string
	for _, f := range review.Items[0].Details.Fields {
		labels = append(labels, f.Label)
	}
	if got := strings.Join(labels, ","); got != ",Bounded authorization operation,Authorization,Rotation" {
		t.Fatalf("field labels = %q", got)
	}
}
