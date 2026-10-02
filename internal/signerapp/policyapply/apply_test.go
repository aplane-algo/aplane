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
	if got, raw := encodedDocumentsSize([]policy.StoredDocument{{Bytes: []byte(quoted)}}), len(quoted); got < raw+1000 {
		t.Fatalf("encoded size %d does not count escaping of a %d-byte document", got, raw)
	}
}
