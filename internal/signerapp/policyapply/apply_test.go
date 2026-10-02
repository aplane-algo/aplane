// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyapply

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
)

// paddedCosignerDoc returns a valid cosigner document of roughly size bytes;
// JSON whitespace pads it without changing its meaning.
func paddedCosignerDoc(key string, size int) string {
	return fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1",%s"key":%q,"transfer_policy":{"routes":[]}}`,
		strings.Repeat(" ", size), key)
}

func witnessKeyID(i int) string {
	return fmt.Sprintf("%c%s", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[i], strings.Repeat("A", 51))
}

func TestCandidateRejectsPolicySetTooLargeForOneAdminMessage(t *testing.T) {
	env := Env{Role: noderole.RoleCosigner}
	current := &policyruntime.NodePolicy{Role: noderole.RoleCosigner}
	for i := range 4 {
		current.Documents = append(current.Documents, policy.StoredDocument{
			Key: witnessKeyID(i), Bytes: []byte(paddedCosignerDoc(witnessKeyID(i), 850<<10)),
		})
	}
	if _, problems, err := Candidate(env, current, nil, []string{witnessKeyID(0)}); err != nil || len(problems) != 0 {
		t.Fatalf("removing from a large set: problems %v, err %v", problems, err)
	}

	fifth := adminproto.PolicyDocument{Key: witnessKeyID(4), Document: paddedCosignerDoc(witnessKeyID(4), 850<<10)}
	_, _, err := Candidate(env, current, []adminproto.PolicyDocument{fifth}, nil)
	if Code(err, "") != "policy_set_too_large" {
		t.Fatalf("Candidate(fifth large document) error = %v, want policy_set_too_large", err)
	}

	// Escaping counts: a document of quotes doubles on the wire.
	quoted := fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","description":%q,"key":%q,"transfer_policy":{"routes":[]}}`,
		strings.Repeat(`"`, 1000), witnessKeyID(5))
	if got := policyResponseSize(env, []policy.StoredDocument{{Key: witnessKeyID(5), Bytes: []byte(quoted)}}); got < 2*len(quoted) {
		t.Fatalf("response size %d does not count escaping of a %d-byte document", got, len(quoted))
	}
}

// manyWitnessKeyIDs returns n distinct valid Witness Key IDs.
func manyWitnessKeyIDs(n int) []string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	ids := make([]string, n)
	for i := range n {
		ids[i] = string([]byte{alphabet[i/1024%32], alphabet[i/32%32], alphabet[i%32]}) + strings.Repeat("A", 49)
	}
	return ids
}

// TestCandidateCountsKeyStatusesInResponseSize reproduces many small
// documents whose key statuses, not their bytes, overflow the response.
func TestCandidateCountsKeyStatusesInResponseSize(t *testing.T) {
	keys := manyWitnessKeyIDs(3500)
	held := map[string]bool{}
	for _, key := range keys {
		held[key] = true
	}
	env := Env{Role: noderole.RoleCosigner, HeldKeys: held}
	current := &policyruntime.NodePolicy{Role: noderole.RoleCosigner}
	docs := make([]adminproto.PolicyDocument, len(keys))
	for i, key := range keys {
		docs[i] = adminproto.PolicyDocument{Key: key, Document: paddedCosignerDoc(key, 860)}
	}
	if _, _, err := Candidate(env, current, docs, nil); Code(err, "") != "policy_set_too_large" {
		t.Fatalf("Candidate(3500 documents) error = %v, want policy_set_too_large", err)
	}

	accepted := docs[:3000]
	candidate, problems, err := Candidate(env, current, accepted, nil)
	if err != nil || len(problems) != 0 {
		t.Fatalf("Candidate(3000 documents) = %v, %v", problems, err)
	}
	wire := View(candidate, held, generationIDPlaceholder).Wire(strings.Repeat("i", 256))
	encoded, err := protocol.MarshalAdminMessage(protocol.ApplyPolicyResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeApplyPolicyResult, ID: strings.Repeat("i", 256)},
		Success:     true,
		Policy:      &wire,
	})
	if err != nil || len(encoded) > protocol.MaxAdminMessageBytes {
		t.Fatalf("accepted policy encodes to %d bytes, frame limit %d (%v)", len(encoded), protocol.MaxAdminMessageBytes, err)
	}
}
