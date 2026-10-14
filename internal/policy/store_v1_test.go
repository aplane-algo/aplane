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

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const testWitnessKeyIDV1b = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func testPolicyGeneration(t *testing.T) storepaths.GenPaths {
	t.Helper()
	gen := storepaths.StagedGenerationPaths("gen-1753500000-0badc0de", t.TempDir())
	for _, dir := range []string{gen.PoliciesDir(), gen.DeletedPoliciesDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return gen
}

func TestDefaultPolicyRoundTripsExactBytes(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	data := signerJSON(t, DefaultKey, `{"reject_clawback": true}`)
	if err := WriteDefault(gen, noderole.RoleSigner, data, kr, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	doc, decoded, err := LoadVerifiedDefault(gen, noderole.RoleSigner, kr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(doc.Bytes, data) || doc.Key != DefaultKey || !decoded.RejectClawback {
		t.Fatalf("loaded %q key %q", doc.Bytes, doc.Key)
	}
	if _, _, err := LoadVerifiedDefault(gen, noderole.RoleCosigner, kr); err == nil {
		t.Fatal("a signer default loaded on a cosigner node")
	}

	if err := os.WriteFile(gen.DefaultPolicyPath(), append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadVerifiedDefault(gen, noderole.RoleSigner, kr); !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("tampered load error = %v, want mismatch", err)
	}
}

func TestWritePolicyRejectsInvalidDocuments(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	var docErr *DocumentError
	if err := WriteDefault(gen, noderole.RoleSigner, cosignerJSON(t, DefaultKey, ""), kr, time.Time{}); !errors.As(err, &docErr) {
		t.Fatalf("WriteDefault(cosigner doc) error = %v, want DocumentError", err)
	}
	if err := WriteKeyPolicy(gen, noderole.RoleCosigner, testWitnessKeyIDV1b, cosignerJSON(t, testWitnessKeyIDV1, ""), kr, time.Time{}); !errors.As(err, &docErr) {
		t.Fatalf("WriteKeyPolicy(key mismatch) error = %v, want DocumentError", err)
	}
	if err := WriteKeyPolicy(gen, noderole.RoleSigner, DefaultKey, signerJSON(t, DefaultKey, ""), kr, time.Time{}); err == nil {
		t.Fatal("WriteKeyPolicy accepted the default key as a selector")
	}
	if _, err := os.Stat(gen.DefaultPolicyPath()); !os.IsNotExist(err) {
		t.Fatalf("rejected write left a file: %v", err)
	}
}

func TestKeyPoliciesLoadSortedAndDigestTracksChanges(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	for _, key := range []string{testWitnessKeyIDV1, testWitnessKeyIDV1b} {
		if err := WriteKeyPolicy(gen, noderole.RoleCosigner, key, cosignerJSON(t, key, ""), kr, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := LoadVerifiedKeyPolicies(gen, noderole.RoleCosigner, kr)
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

	if err := RemoveKeyPolicy(gen, testWitnessKeyIDV1b); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveKeyPolicy(gen, testWitnessKeyIDV1); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadVerifiedKeyPolicies(gen, noderole.RoleCosigner, kr); err != nil || len(loaded) != 0 {
		t.Fatalf("after remove/archive: %v, %v", loaded, err)
	}
	for _, name := range []string{testWitnessKeyIDV1 + ".json", testWitnessKeyIDV1 + ".json.hmac"} {
		if _, err := os.Stat(filepath.Join(gen.DeletedPoliciesDir(), name)); err != nil {
			t.Fatalf("archive missing %s: %v", name, err)
		}
	}
	if err := ArchiveKeyPolicy(gen, testWitnessKeyIDV1); err != nil {
		t.Fatalf("archiving an absent policy error = %v, want nil", err)
	}
	if err := RemoveKeyPolicy(gen, testWitnessKeyIDV1); err == nil {
		t.Fatal("removing an absent policy succeeded")
	}
}

func TestSignerKeyPoliciesUseAddressSelectors(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	key := v1Ops.String()
	if err := WriteKeyPolicy(gen, noderole.RoleSigner, key, signerJSON(t, key, ""), kr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	doc, ok, err := LoadVerifiedKeyPolicy(gen, noderole.RoleSigner, key, kr)
	if err != nil || !ok || doc.Key != key {
		t.Fatalf("LoadVerifiedKeyPolicy = %v, %v, %v", doc.Key, ok, err)
	}
	if _, _, err := LoadVerifiedKeyPolicy(gen, noderole.RoleCosigner, key, kr); err == nil {
		t.Fatal("a signer key policy loaded on a cosigner node")
	}
}

func TestKeyPoliciesRejectIncompleteOrForeignEntries(t *testing.T) {
	kr := policyIntegrityTestKey(t)
	for name, setup := range map[string]func(gen storepaths.GenPaths) error{
		"document without sidecar": func(gen storepaths.GenPaths) error {
			return os.WriteFile(gen.PolicyPath(testWitnessKeyIDV1), cosignerJSON(t, testWitnessKeyIDV1, ""), 0o600)
		},
		"sidecar without document": func(gen storepaths.GenPaths) error {
			return os.WriteFile(gen.PolicyPath(testWitnessKeyIDV1)+".hmac", []byte("{}"), 0o600)
		},
		"foreign file": func(gen storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(gen.PoliciesDir(), "notes.txt"), nil, 0o600)
		},
		"default in the key namespace": func(gen storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(gen.PoliciesDir(), "default.json"), nil, 0o600)
		},
		"lowercase key": func(gen storepaths.GenPaths) error {
			return os.WriteFile(filepath.Join(gen.PoliciesDir(), "myjze3uf7g4jxr5stmqk5tsl5fne7pe224bsklz2h4ajwjipbebq.json"), nil, 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			gen := testPolicyGeneration(t)
			if err := setup(gen); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadVerifiedKeyPolicies(gen, noderole.RoleCosigner, kr); err == nil {
				t.Fatal("LoadVerifiedKeyPolicies() accepted the namespace")
			}
		})
	}
}

func TestResignPoliciesValidatesHandPlacedDocuments(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	if err := os.WriteFile(gen.DefaultPolicyPath(), cosignerJSON(t, DefaultKey, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gen.PolicyPath(testWitnessKeyIDV1), cosignerJSON(t, testWitnessKeyIDV1, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResignDefault(gen, noderole.RoleCosigner, kr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := ResignKeyPolicies(gen, noderole.RoleCosigner, kr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadVerifiedDefault(gen, noderole.RoleCosigner, kr); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadVerifiedKeyPolicies(gen, noderole.RoleCosigner, kr); err != nil || len(loaded) != 1 {
		t.Fatalf("resigned load = %v, %v", loaded, err)
	}

	if err := os.WriteFile(gen.DefaultPolicyPath(), []byte(`{"format":"aplane.policy.v1","bogus":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var docErr *DocumentError
	if err := ResignDefault(gen, noderole.RoleCosigner, kr, time.Time{}); !errors.As(err, &docErr) {
		t.Fatalf("ResignDefault(invalid) error = %v, want DocumentError", err)
	}
}

func TestLoadVerifiedDefaultReportsMissingFileAndWrongKey(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	if _, _, err := LoadVerifiedDefault(gen, noderole.RoleSigner, kr); !errors.Is(err, ErrPolicyIntegrityMissingFile) {
		t.Fatalf("missing policy error = %v, want ErrPolicyIntegrityMissingFile", err)
	}
	if err := WriteEmbeddedDefault(gen, noderole.RoleSigner, kr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	other := cryptotest.Keyring(t, bytes.Repeat([]byte{0x42}, 32))
	if _, _, err := LoadVerifiedDefault(gen, noderole.RoleSigner, other); !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("wrong-key error = %v, want ErrPolicyIntegrityMismatch", err)
	}
}

func TestLoadVerifiedKeyPolicyRejectsOrphanSidecar(t *testing.T) {
	gen := testPolicyGeneration(t)
	kr := policyIntegrityTestKey(t)
	if _, ok, err := LoadVerifiedKeyPolicy(gen, noderole.RoleCosigner, testWitnessKeyIDV1, kr); ok || err != nil {
		t.Fatalf("absent pair = %v, %v; want no policy and no error", ok, err)
	}
	if err := WriteKeyPolicy(gen, noderole.RoleCosigner, testWitnessKeyIDV1, cosignerJSON(t, testWitnessKeyIDV1, ""), kr, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(gen.PolicyPath(testWitnessKeyIDV1)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := LoadVerifiedKeyPolicy(gen, noderole.RoleCosigner, testWitnessKeyIDV1, kr); ok || !errors.Is(err, ErrPolicyIntegrityMissingFile) {
		t.Fatalf("orphan sidecar = %v, %v; want ErrPolicyIntegrityMissingFile", ok, err)
	}
}
