// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const testWitnessKeyIDV1b = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func testPolicyGeneration(t *testing.T) storepaths.GenPaths {
	t.Helper()
	gen := storepaths.StagedGenerationPaths("gen-1753500000-0badc0de", t.TempDir())
	for _, dir := range []string{gen.CosignerPoliciesDir(), gen.DeletedCosignerPoliciesDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return gen
}

func cosignerDocV1(key string) []byte {
	return []byte(fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"transfer_policy":{"routes":[]}}`+"\n", key))
}

func TestSignerPolicyRoundTripsExactBytes(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	data := []byte("{\n  \"format\": \"aplane.signer-policy.v1\",\n  \"reject_clawback\": true\n}\n")
	if err := WriteSignerPolicy(gen, data, kr, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	doc, decoded, err := LoadVerifiedSignerPolicy(gen, kr)
	if err != nil {
		t.Fatal(err)
	}
	if string(doc.Bytes) != string(data) || doc.Key != "" || decoded.RejectClawback == nil || !*decoded.RejectClawback {
		t.Fatalf("loaded %q key %q", doc.Bytes, doc.Key)
	}

	if err := os.WriteFile(gen.PolicyPath(), append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadVerifiedSignerPolicy(gen, kr); !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("tampered load error = %v, want mismatch", err)
	}
}

func TestWritePolicyRejectsInvalidDocuments(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	var docErr *DocumentError
	if err := WriteSignerPolicy(gen, []byte(`{"format":"aplane.cosigner-policy.v1"}`), kr, time.Time{}); !errors.As(err, &docErr) {
		t.Fatalf("WriteSignerPolicy(cosigner doc) error = %v, want DocumentError", err)
	}
	if err := WriteCosignerPolicy(gen, testWitnessKeyIDV1b, cosignerDocV1(testWitnessKeyIDV1), kr, time.Time{}); !errors.As(err, &docErr) {
		t.Fatalf("WriteCosignerPolicy(key mismatch) error = %v, want DocumentError", err)
	}
	if _, err := os.Stat(gen.PolicyPath()); !os.IsNotExist(err) {
		t.Fatalf("rejected write left a file: %v", err)
	}
}

func TestCosignerPoliciesLoadSortedAndDigestTracksChanges(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	for _, key := range []string{testWitnessKeyIDV1, testWitnessKeyIDV1b} {
		if err := WriteCosignerPolicy(gen, key, cosignerDocV1(key), kr, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := LoadVerifiedCosignerPolicies(gen, kr)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 || loaded[0].Document.Key != testWitnessKeyIDV1b || loaded[1].Document.Key != testWitnessKeyIDV1 {
		t.Fatalf("loaded keys = %v", loaded)
	}
	docs := []StoredDocument{loaded[0].Document, loaded[1].Document}
	before := PolicySetSHA256(docs)
	if PolicySetSHA256([]StoredDocument{docs[1], docs[0]}) != before {
		t.Fatal("PolicySetSHA256 depends on order")
	}
	if PolicySetSHA256(docs[:1]) == before {
		t.Fatal("PolicySetSHA256 ignores a removed document")
	}

	if err := RemoveCosignerPolicy(gen, testWitnessKeyIDV1b); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveCosignerPolicy(gen, testWitnessKeyIDV1); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadVerifiedCosignerPolicies(gen, kr); err != nil || len(loaded) != 0 {
		t.Fatalf("after remove/archive: %v, %v", loaded, err)
	}
	for _, name := range []string{testWitnessKeyIDV1 + ".json", testWitnessKeyIDV1 + ".json.hmac"} {
		if _, err := os.Stat(filepath.Join(gen.DeletedCosignerPoliciesDir(), name)); err != nil {
			t.Fatalf("archive missing %s: %v", name, err)
		}
	}
	if err := ArchiveCosignerPolicy(gen, testWitnessKeyIDV1); err != nil {
		t.Fatalf("archiving an absent policy error = %v, want nil", err)
	}
	if err := RemoveCosignerPolicy(gen, testWitnessKeyIDV1); err == nil {
		t.Fatal("removing an absent policy succeeded")
	}
}

func TestCosignerPoliciesRejectIncompleteOrForeignEntries(t *testing.T) {
	kr := policyIntegrityTestKey(t)
	for name, setup := range map[string]func(gen storepaths.GenPaths) error{
		"document without sidecar": func(gen storepaths.GenPaths) error {
			return os.WriteFile(gen.CosignerPolicyPath(testWitnessKeyIDV1), cosignerDocV1(testWitnessKeyIDV1), 0o600)
		},
		"sidecar without document": func(gen storepaths.GenPaths) error {
			return os.WriteFile(gen.CosignerPolicyPath(testWitnessKeyIDV1)+".hmac", []byte("{}"), 0o600)
		},
		"foreign file": func(gen storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(gen.CosignerPoliciesDir(), "notes.txt"), nil, 0o600)
		},
		"lowercase key": func(gen storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(gen.CosignerPoliciesDir(), "myjze3uf7g4jxr5stmqk5tsl5fne7pe224bsklz2h4ajwjipbebq.json"), nil, 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			gen := testPolicyGeneration(t)
			if err := setup(gen); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadVerifiedCosignerPolicies(gen, kr); err == nil {
				t.Fatal("LoadVerifiedCosignerPolicies() accepted the namespace")
			}
		})
	}
}

func TestResignPoliciesValidatesHandPlacedDocuments(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	if err := os.WriteFile(gen.PolicyPath(), []byte(`{"format":"aplane.signer-policy.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gen.CosignerPolicyPath(testWitnessKeyIDV1), cosignerDocV1(testWitnessKeyIDV1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResignSignerPolicy(gen, kr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := ResignCosignerPolicies(gen, kr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadVerifiedSignerPolicy(gen, kr); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadVerifiedCosignerPolicies(gen, kr); err != nil || len(loaded) != 1 {
		t.Fatalf("resigned cosigner load = %v, %v", loaded, err)
	}

	if err := os.WriteFile(gen.PolicyPath(), []byte(`{"format":"aplane.signer-policy.v1","bogus":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var docErr *DocumentError
	if err := ResignSignerPolicy(gen, kr, time.Time{}); !errors.As(err, &docErr) {
		t.Fatalf("ResignSignerPolicy(invalid) error = %v, want DocumentError", err)
	}
}

func TestLoadVerifiedSignerPolicyReportsMissingFileAndWrongKey(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	if _, _, err := LoadVerifiedSignerPolicy(gen, kr); !errors.Is(err, ErrPolicyIntegrityMissingFile) {
		t.Fatalf("missing policy error = %v, want ErrPolicyIntegrityMissingFile", err)
	}
	if err := WriteInitialSignerPolicy(gen, kr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	other := cryptotest.Keyring(t, bytes.Repeat([]byte{0x42}, 32))
	if _, _, err := LoadVerifiedSignerPolicy(gen, other); !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("wrong-key error = %v, want ErrPolicyIntegrityMismatch", err)
	}
}
