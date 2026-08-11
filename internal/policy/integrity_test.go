// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
)

func TestPolicyIntegrityRoundTrip(t *testing.T) {
	key := policyIntegrityTestKey(t)
	policyBytes := []byte("reject_foreign_rekey: true\n")
	sidecar, err := SignPolicyIntegrity(policyBytes, key, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("SignPolicyIntegrity() error = %v", err)
	}

	if sidecar.Version != PolicyIntegritySidecarVersion {
		t.Fatalf("Version = %d, want %d", sidecar.Version, PolicyIntegritySidecarVersion)
	}
	if sidecar.Algorithm != PolicyIntegrityAlgorithm {
		t.Fatalf("Algorithm = %q, want %q", sidecar.Algorithm, PolicyIntegrityAlgorithm)
	}
	if sidecar.KeyID != PolicyIntegrityKeyID {
		t.Fatalf("KeyID = %q, want %q", sidecar.KeyID, PolicyIntegrityKeyID)
	}
	if sidecar.IntegrityTerm != 1 {
		t.Fatalf("IntegrityTerm = %d, want 1", sidecar.IntegrityTerm)
	}
	if got := sidecar.PolicySHA256; got != PolicySHA256(policyBytes) {
		t.Fatalf("PolicySHA256 = %q, want %q", got, PolicySHA256(policyBytes))
	}
	if err := VerifyPolicyIntegrity(policyBytes, sidecar, key); err != nil {
		t.Fatalf("VerifyPolicyIntegrity() error = %v", err)
	}

	encoded, err := MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		t.Fatalf("MarshalPolicyIntegritySidecar() error = %v", err)
	}
	if bytes.Contains(encoded, []byte("policy_mtime_ns")) {
		t.Fatalf("new sidecar contains legacy policy_mtime_ns: %s", encoded)
	}
	parsed, err := ParsePolicyIntegritySidecar(encoded)
	if err != nil {
		t.Fatalf("ParsePolicyIntegritySidecar() error = %v", err)
	}
	if err := VerifyPolicyIntegrity(policyBytes, parsed, key); err != nil {
		t.Fatalf("VerifyPolicyIntegrity(parsed) error = %v", err)
	}
}

func TestPolicyIntegrityRejectsPolicyByteChange(t *testing.T) {
	key := policyIntegrityTestKey(t)
	sidecar, err := SignPolicyIntegrity([]byte("reject_foreign_rekey: true\n"), key, time.Time{})
	if err != nil {
		t.Fatalf("SignPolicyIntegrity() error = %v", err)
	}

	err = VerifyPolicyIntegrity([]byte("reject_foreign_rekey: false\n"), sidecar, key)
	if !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("VerifyPolicyIntegrity() error = %v, want ErrPolicyIntegrityMismatch", err)
	}
	if !errors.Is(err, ErrPolicyIntegrity) {
		t.Fatalf("VerifyPolicyIntegrity() error = %v, want ErrPolicyIntegrity", err)
	}
}

func TestPolicyIntegrityDiagnosticFieldsAreNotTrusted(t *testing.T) {
	key := policyIntegrityTestKey(t)
	policyBytes := []byte("max_fee_microalgos: 1000\n")
	sidecar, err := SignPolicyIntegrity(policyBytes, key, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("SignPolicyIntegrity() error = %v", err)
	}

	sidecar.PolicySHA256 = "not-the-policy-sha"
	sidecar.SignedAtUnix = 1
	sidecar.PolicyMTimeNS = 2
	if err := VerifyPolicyIntegrity(policyBytes, sidecar, key); err != nil {
		t.Fatalf("VerifyPolicyIntegrity() error = %v", err)
	}
}

func TestPolicyIntegrityRejectsUnsupportedSecurityFields(t *testing.T) {
	key := policyIntegrityTestKey(t)
	policyBytes := []byte("{}\n")
	base, err := SignPolicyIntegrity(policyBytes, key, time.Time{})
	if err != nil {
		t.Fatalf("SignPolicyIntegrity() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*IntegritySidecar)
	}{
		{name: "version", mutate: func(s *IntegritySidecar) { s.Version = 1 }},
		{name: "algorithm", mutate: func(s *IntegritySidecar) { s.Algorithm = "hmac-sha3-256" }},
		{name: "key id", mutate: func(s *IntegritySidecar) { s.KeyID = "other-key" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sidecar := *base
			tt.mutate(&sidecar)
			err := VerifyPolicyIntegrity(policyBytes, &sidecar, key)
			if !errors.Is(err, ErrPolicyIntegrityUnsupported) {
				t.Fatalf("VerifyPolicyIntegrity() error = %v, want ErrPolicyIntegrityUnsupported", err)
			}
		})
	}
}

func TestPolicyIntegrityRejectsBadSidecarHMAC(t *testing.T) {
	key := policyIntegrityTestKey(t)
	sidecar, err := SignPolicyIntegrity([]byte("{}\n"), key, time.Time{})
	if err != nil {
		t.Fatalf("SignPolicyIntegrity() error = %v", err)
	}
	sidecar.HMAC = "not-hex"

	err = VerifyPolicyIntegrity([]byte("{}\n"), sidecar, key)
	if !errors.Is(err, ErrPolicyIntegrityBadSidecar) {
		t.Fatalf("VerifyPolicyIntegrity() error = %v, want ErrPolicyIntegrityBadSidecar", err)
	}
}

func TestPolicyIntegrityRejectsUnauthorizedTerm(t *testing.T) {
	kr := policyIntegrityTestKey(t)
	sidecar, err := SignPolicyIntegrity([]byte("{}\n"), kr, time.Time{})
	if err != nil {
		t.Fatalf("SignPolicyIntegrity() error = %v", err)
	}
	sidecar.IntegrityTerm++
	err = VerifyPolicyIntegrity([]byte("{}\n"), sidecar, kr)
	if !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("VerifyPolicyIntegrity() error = %v, want ErrPolicyIntegrityMismatch", err)
	}
}

func TestPolicyIntegritySidecarParsingIsStrict(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"version":2,"unknown":true}`),
		[]byte(`{"version":2}{}`),
	} {
		if _, err := ParsePolicyIntegritySidecar(data); !errors.Is(err, ErrPolicyIntegrityBadSidecar) {
			t.Fatalf("ParsePolicyIntegritySidecar(%q) error = %v, want ErrPolicyIntegrityBadSidecar", data, err)
		}
	}
}

func TestPolicyIntegrityRejectsMissingKeyring(t *testing.T) {
	_, err := SignPolicyIntegrity([]byte("{}\n"), nil, time.Time{})
	if !errors.Is(err, ErrPolicyIntegrityBadSidecar) {
		t.Fatalf("SignPolicyIntegrity() error = %v, want ErrPolicyIntegrityBadSidecar", err)
	}

	err = VerifyPolicyIntegrity([]byte("{}\n"), &IntegritySidecar{}, nil)
	if !errors.Is(err, ErrPolicyIntegrityBadSidecar) {
		t.Fatalf("VerifyPolicyIntegrity() error = %v, want ErrPolicyIntegrityBadSidecar", err)
	}
}

func TestLoadPolicyIntegritySidecarMissing(t *testing.T) {
	_, err := LoadPolicyIntegritySidecar(filepath.Join(t.TempDir(), "policy.yaml.hmac"))
	if !errors.Is(err, ErrPolicyIntegrityMissingSidecar) {
		t.Fatalf("LoadPolicyIntegritySidecar() error = %v, want ErrPolicyIntegrityMissingSidecar", err)
	}
}

func TestLoadPolicyIntegritySidecar(t *testing.T) {
	key := policyIntegrityTestKey(t)
	policyBytes := []byte("{}\n")
	sidecar, err := SignPolicyIntegrity(policyBytes, key, time.Time{})
	if err != nil {
		t.Fatalf("SignPolicyIntegrity() error = %v", err)
	}
	encoded, err := MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		t.Fatalf("MarshalPolicyIntegritySidecar() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "policy.yaml.hmac")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	loaded, err := LoadPolicyIntegritySidecar(path)
	if err != nil {
		t.Fatalf("LoadPolicyIntegritySidecar() error = %v", err)
	}
	if err := VerifyPolicyIntegrity(policyBytes, loaded, key); err != nil {
		t.Fatalf("VerifyPolicyIntegrity(loaded) error = %v", err)
	}
}

func policyIntegrityTestKey(t *testing.T) *apcrypto.Keyring {
	t.Helper()
	return cryptotest.Keyring(t, []byte("01234567890123456789012345678901"))
}
