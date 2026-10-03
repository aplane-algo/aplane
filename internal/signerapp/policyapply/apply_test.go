// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyapply

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
)

// manyWitnessKeyIDs returns n distinct valid Witness Key IDs.
func manyWitnessKeyIDs(n int) []string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	ids := make([]string, n)
	for i := range n {
		ids[i] = string([]byte{alphabet[i/1024%32], alphabet[i/32%32], alphabet[i%32]}) + strings.Repeat("A", 49)
	}
	return ids
}

func cosignerDoc(key string) string {
	return fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"transfer_policy":{"routes":[]}}`, key)
}

func TestCandidateCapsCosignerPolicyDocuments(t *testing.T) {
	ids := manyWitnessKeyIDs(MaxCosignerPolicies + 1)
	env := Env{Role: noderole.RoleCosigner}
	current := &policyruntime.NodePolicy{Role: noderole.RoleCosigner}
	for _, key := range ids[:MaxCosignerPolicies] {
		current.Documents = append(current.Documents, policy.StoredDocument{Key: key, Bytes: []byte(cosignerDoc(key))})
	}
	last := ids[MaxCosignerPolicies]
	_, _, err := Candidate(env, current, []adminproto.PolicyDocument{{Key: last, Document: cosignerDoc(last)}}, nil)
	if Code(err, "") != "policy_set_too_large" {
		t.Fatalf("Candidate(one past the cap) error = %v, want policy_set_too_large", err)
	}
	// Replacing and removing documents stay possible at the cap.
	replace := []adminproto.PolicyDocument{{Key: ids[0], Document: cosignerDoc(ids[0])}}
	if _, problems, err := Candidate(env, current, replace, []string{ids[1]}); err != nil || len(problems) != 0 {
		t.Fatalf("Candidate(replace and remove at the cap) = %v, %v", problems, err)
	}
}

// TestPolicySummaryFitsOneAdminMessageAtTheCaps encodes the largest possible
// get_policy summary, carried inside an apply_policy result: the cap of
// documents for keys the node does not hold, the cap of held keys without
// documents, and every field at its longest.
func TestPolicySummaryFitsOneAdminMessageAtTheCaps(t *testing.T) {
	ids := manyWitnessKeyIDs(MaxCosignerPolicies + keys.MaxCosignerCredentials)
	held := map[string]bool{}
	for _, key := range ids[MaxCosignerPolicies:] {
		held[key] = true
	}
	view := View(&policyruntime.NodePolicy{Role: noderole.RoleCosigner}, held, "")
	for _, key := range ids[:MaxCosignerPolicies] {
		view.Documents = append(view.Documents, adminproto.PolicyDocumentInfo{
			Key: key, SHA256: strings.Repeat("f", 64), Size: 1 << 20, SignedAtUnix: math.MaxInt64,
		})
		view.Keys = append(view.Keys, adminproto.PolicyKeyStatus{Key: key, Status: adminproto.PolicyKeyNotHeld})
	}
	view.PolicySetSHA256 = strings.Repeat("f", 64)
	view.GenerationID = "gen-9999999999-ffffffff"
	if len(view.Keys) != MaxCosignerPolicies+keys.MaxCosignerCredentials {
		t.Fatalf("key statuses = %d", len(view.Keys))
	}
	id := strings.Repeat("i", 4096)
	wire := view.Wire(id)
	encoded, err := protocol.MarshalAdminMessage(protocol.ApplyPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeApplyPolicyResult, ID: id},
		Success:     true,
		Policy:      &wire,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("worst-case summary: %d bytes of %d", len(encoded), protocol.MaxAdminMessageBytes)
	if len(encoded) > protocol.MaxAdminMessageBytes {
		t.Fatalf("worst-case policy summary is %d bytes; the admin frame allows %d", len(encoded), protocol.MaxAdminMessageBytes)
	}
}

func TestDocumentReturnsExactBytesOrNotFound(t *testing.T) {
	ids := manyWitnessKeyIDs(2)
	np := &policyruntime.NodePolicy{Role: noderole.RoleCosigner, Documents: []policy.StoredDocument{{Key: ids[0], Bytes: []byte(cosignerDoc(ids[0]))}}}
	if got := Document(np, ids[0]); !got.Success || got.Document != cosignerDoc(ids[0]) || got.SHA256 == "" {
		t.Fatalf("Document(held) = %+v", got)
	}
	for _, key := range []string{ids[1], ""} {
		if got := Document(np, key); got.Success || got.Code != "policy_document_not_found" {
			t.Fatalf("Document(%q) = %+v", key, got)
		}
	}
	if got := Document(nil, ""); got.Code != "policy_unavailable" {
		t.Fatalf("Document(no policy) = %+v", got)
	}
}
