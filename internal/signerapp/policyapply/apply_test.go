// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyapply

import (
	"math"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
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
	return policytest.MustDocument(noderole.RoleCosigner, key, "")
}

func cosignerDefaultDoc() policy.StoredDocument {
	return policy.StoredDocument{Key: policy.DefaultKey, Bytes: []byte(policytest.MustDocument(noderole.RoleCosigner, policy.DefaultKey, ""))}
}

func TestCandidateCapsKeyPolicyDocuments(t *testing.T) {
	ids := manyWitnessKeyIDs(MaxPolicies + 1)
	env := Env{Role: noderole.RoleCosigner}
	current := &policyruntime.NodePolicy{Role: noderole.RoleCosigner, Documents: []policy.StoredDocument{cosignerDefaultDoc()}}
	for _, key := range ids[:MaxPolicies] {
		current.Documents = append(current.Documents, policy.StoredDocument{Key: key, Bytes: []byte(cosignerDoc(key))})
	}
	last := ids[MaxPolicies]
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

func TestCandidateKeepsTheDefaultAndRefusesItsRemoval(t *testing.T) {
	env := Env{Role: noderole.RoleCosigner}
	current := &policyruntime.NodePolicy{Role: noderole.RoleCosigner, Documents: []policy.StoredDocument{cosignerDefaultDoc()}}
	key := manyWitnessKeyIDs(1)[0]
	if _, _, err := Candidate(env, current, nil, []string{policy.DefaultKey}); Code(err, "") != "invalid_policy_request" {
		t.Fatalf("Candidate(remove default) error = %v, want invalid_policy_request", err)
	}
	if _, _, err := Candidate(env, current, nil, []string{key}); Code(err, "") != "invalid_policy_request" {
		t.Fatalf("Candidate(remove a key without its own policy) error = %v, want invalid_policy_request", err)
	}
	if _, _, err := Candidate(env, current, []adminproto.PolicyDocument{{Key: "", Document: cosignerDoc(key)}}, nil); Code(err, "") != "invalid_policy_request" {
		t.Fatalf("Candidate(unkeyed document) error = %v, want invalid_policy_request", err)
	}
	candidate, problems, err := Candidate(env, current, []adminproto.PolicyDocument{{Key: key, Document: cosignerDoc(key)}}, nil)
	if err != nil || len(problems) != 0 || candidate == nil || candidate.Default == nil || candidate.Keys[key] == nil {
		t.Fatalf("Candidate(add a key) = %+v, %v, %v", candidate, problems, err)
	}
	if candidate.PolicyFor(key) != candidate.Keys[key] || candidate.PolicyFor("other") != candidate.Default {
		t.Fatal("PolicyFor did not select the key's own document and the default")
	}
	// A store with no default cannot be changed into one without a default.
	if _, _, err := Candidate(env, &policyruntime.NodePolicy{Role: noderole.RoleCosigner}, []adminproto.PolicyDocument{{Key: key, Document: cosignerDoc(key)}}, nil); Code(err, "") != "invalid_policy_request" {
		t.Fatalf("Candidate(no default) error = %v, want invalid_policy_request", err)
	}
	// A document for the wrong role is a problem, not an error.
	wrongRole := policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey, "")
	_, problems, err = Candidate(env, current, []adminproto.PolicyDocument{{Key: policy.DefaultKey, Document: wrongRole}}, nil)
	if err != nil || len(problems) != 1 || problems[0].Pointer != "/role" {
		t.Fatalf("Candidate(wrong role) = %+v, %v", problems, err)
	}
}

// TestPolicySummaryFitsOneAdminMessageAtTheCaps encodes the largest possible
// get_policy summary, carried inside an apply_policy result: the cap of
// documents for keys the node does not hold, the cap of held keys on the
// default, and every field at its longest.
func TestPolicySummaryFitsOneAdminMessageAtTheCaps(t *testing.T) {
	ids := manyWitnessKeyIDs(MaxPolicies + keys.MaxCosignerCredentials)
	held := map[string]bool{}
	for _, key := range ids[MaxPolicies:] {
		held[key] = true
	}
	view := View(&policyruntime.NodePolicy{Role: noderole.RoleCosigner, Documents: []policy.StoredDocument{cosignerDefaultDoc()}}, held, "")
	for _, key := range ids[:MaxPolicies] {
		view.Documents = append(view.Documents, adminproto.PolicyDocumentInfo{
			Key: key, SHA256: strings.Repeat("f", 64), Size: 1 << 20, SignedAtUnix: math.MaxInt64,
		})
		view.Keys = append(view.Keys, adminproto.PolicyKeyStatus{Key: key, Status: adminproto.PolicyKeyNotHeld})
	}
	view.PolicySetSHA256 = strings.Repeat("f", 64)
	view.GenerationID = "gen-9999999999-ffffffff"
	if len(view.Keys) != MaxPolicies+keys.MaxCosignerCredentials {
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

func TestKeyStatusAndCoverageWarnings(t *testing.T) {
	ids := manyWitnessKeyIDs(3)
	np := &policyruntime.NodePolicy{Role: noderole.RoleCosigner, Documents: []policy.StoredDocument{
		cosignerDefaultDoc(),
		{Key: ids[0], Bytes: []byte(cosignerDoc(ids[0]))},
		{Key: ids[2], Bytes: []byte(cosignerDoc(ids[2]))},
	}}
	statuses := KeyStatus(map[string]bool{ids[0]: true, ids[1]: true}, np)
	want := map[string]string{ids[0]: adminproto.PolicyKeyOwn, ids[1]: adminproto.PolicyKeyDefault, ids[2]: adminproto.PolicyKeyNotHeld}
	if len(statuses) != 3 {
		t.Fatalf("statuses = %+v", statuses)
	}
	for _, st := range statuses {
		if st.Key == policy.DefaultKey || want[st.Key] != st.Status {
			t.Fatalf("statuses = %+v, want %v", statuses, want)
		}
	}
	warnings := CoverageWarnings(statuses)
	if len(warnings) != 1 || warnings[0].Key != ids[2] {
		t.Fatalf("coverage warnings = %+v, want one for the document whose key is not held", warnings)
	}
}

func TestDocumentReturnsExactBytesOrNotFound(t *testing.T) {
	ids := manyWitnessKeyIDs(2)
	np := &policyruntime.NodePolicy{Role: noderole.RoleCosigner, Documents: []policy.StoredDocument{
		cosignerDefaultDoc(), {Key: ids[0], Bytes: []byte(cosignerDoc(ids[0]))},
	}}
	if got := Document(np, ids[0]); !got.Success || got.Document != cosignerDoc(ids[0]) || got.SHA256 == "" {
		t.Fatalf("Document(held) = %+v", got)
	}
	if got := Document(np, policy.DefaultKey); !got.Success || got.Key != policy.DefaultKey {
		t.Fatalf("Document(default) = %+v", got)
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
