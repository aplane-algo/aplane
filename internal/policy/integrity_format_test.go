// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/integritysidecar"
)

// TestMarshalPolicyIntegritySidecarFormat pins the on-disk sidecar bytes,
// including field order.
func TestMarshalPolicyIntegritySidecarFormat(t *testing.T) {
	mac := strings.Repeat("ab", 32)
	sidecar := &IntegritySidecar{
		Header: integritysidecar.Header{
			Version: PolicyIntegritySidecarVersion, Algorithm: PolicyIntegrityAlgorithm, KeyID: PolicyIntegrityKeyID,
			IntegrityTerm: 3, HMAC: mac,
		},
		PolicySHA256: "deadbeef", SignedAtUnix: 1700000000,
	}
	got, err := MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		t.Fatalf("MarshalPolicyIntegritySidecar() error = %v", err)
	}
	want := `{
  "version": 2,
  "algorithm": "hmac-sha256",
  "key_id": "keystore-master-hkdf-v1",
  "integrity_term": 3,
  "hmac": "` + mac + `",
  "policy_sha256": "deadbeef",
  "signed_at_unix": 1700000000
}
`
	if string(got) != want {
		t.Fatalf("sidecar bytes =\n%s\nwant\n%s", got, want)
	}
	parsed, err := ParsePolicyIntegritySidecar(got)
	if err != nil || *parsed != *sidecar {
		t.Fatalf("ParsePolicyIntegritySidecar() = %+v, %v; want %+v", parsed, err, sidecar)
	}

	// The pre-v1 mtime diagnostic is not part of the format.
	withMTime := strings.Replace(string(got), `"signed_at_unix": 1700000000`, `"signed_at_unix": 1700000000, "policy_mtime_ns": 42`, 1)
	if _, err := ParsePolicyIntegritySidecar([]byte(withMTime)); !errors.Is(err, ErrPolicyIntegrityBadSidecar) {
		t.Fatalf("ParsePolicyIntegritySidecar(with policy_mtime_ns) error = %v, want bad sidecar", err)
	}
}
