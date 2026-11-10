// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

const prepareTestReference = "ops-cosigner"

// setupPrepareTest registers an enabled cosigner-gated bounded template and
// imports one cosigner reference, returning that reference's Witness Key ID.
func setupPrepareTest(t *testing.T, keyType, family string) (*productruntime.Runtime, []byte, string) {
	t.Helper()
	configureFalconCompileMock(t)
	ir := setupProductRuntime(t)
	spec, err := composeddsa.ParseTemplateSpec([]byte(`
schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: ` + family + `
version: 1
display_name: Prepare Test
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: refused
  cosigner:
    contract: cosigner1
    required_on: [spend]
teal: |
  pushint 1
  assert
`))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	logicsigdsa.RegisterIfAbsent(provider)
	t.Cleanup(func() { lsigprovider.Unregister(keyType) })
	if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{
		KeyType: keyType, Source: keytypestate.SourceYAMLComposed, State: keytypestate.StateEnabled,
	}); err != nil {
		t.Fatal(err)
	}
	publicKey, keyID := importPrepareReference(t, ir, prepareTestReference, 0x61)
	return ir, publicKey, keyID
}

func importPrepareReference(t *testing.T, ir *productruntime.Runtime, name string, fill byte) ([]byte, string) {
	t.Helper()
	publicKey := bytes.Repeat([]byte{fill}, falconfamily.PublicKeySize)
	keyID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := cosignerrefs.NewExportEnvelope(keyID, witness.Falcon1024V1, hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cosignerrefs.Import(ir.KeyPaths(), name, encoded); err != nil {
		t.Fatal(err)
	}
	return publicKey, keyID
}

func assertNoKeys(t *testing.T, service Service) {
	t.Helper()
	keys, err := service.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("store has %d keys, want none: %+v", len(keys), keys)
	}
}

func TestPrepareGenerateKeyDescribesTheAccountAndCreatesNothing(t *testing.T) {
	const keyType = "test.prepare-describes.v1"
	ir, publicKey, keyID := setupPrepareTest(t, keyType, "prepare-describes")
	service := Service{Runtime: ir}

	prepared, err := service.PrepareGenerateKey(keyType, map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference})
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	if prepared.KeyType != keyType || prepared.CosignerKeyID != keyID {
		t.Fatalf("prepared = %+v, want cosigner %s", prepared, keyID)
	}
	if _, named := prepared.Parameters[cosignerrefs.ParamCosignerName]; named {
		t.Fatalf("Parameters still carry the reference name: %#v", prepared.Parameters)
	}
	if got := prepared.Parameters[boundedmeta.CosignerPublicKeyParameter]; got != hex.EncodeToString(publicKey) {
		t.Fatalf("resolved public key = %q", got)
	}
	if prepared.Bounded == nil || prepared.Bounded.Cosigner == nil || prepared.Bounded.Layer3Policy != boundedmeta.Layer3PolicyCustom {
		t.Fatalf("Bounded = %+v", prepared.Bounded)
	}
	if want := lsigprovider.TemplateFingerprintForKeyType(keyType); prepared.Fingerprint == "" || prepared.Fingerprint != want {
		t.Fatalf("Fingerprint = %q, want %q", prepared.Fingerprint, want)
	}
	assertNoKeys(t, service)
}

// Apadmin submits the reviewed public key, not the name, so editing the
// reference afterward cannot change who the account depends on.
func TestReviewedGenerationKeepsTheReviewedAuthority(t *testing.T) {
	const keyType = "test.prepare-reviewed.v1"
	ir, publicKey, _ := setupPrepareTest(t, keyType, "prepare-reviewed")
	service := Service{Runtime: ir}
	prepared, err := service.PrepareGenerateKey(keyType, map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference})
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}

	if deleted, err := cosignerrefs.Delete(ir.KeyPaths(), prepareTestReference); err != nil || !deleted {
		t.Fatalf("delete reference = (%v, %v)", deleted, err)
	}
	importPrepareReference(t, ir, prepareTestReference, 0x62)

	result, err := service.GenerateReviewedKey(context.Background(), keyType, prepared.Parameters, ReviewedValues{Fingerprint: prepared.ReviewFingerprint}, nil)
	if err != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	summary := ir.KeyStore().GetSigningSummary()[result.Address]
	if got := summary.Parameters[boundedmeta.CosignerPublicKeyParameter]; got != hex.EncodeToString(publicKey) {
		t.Fatalf("stored cosigner = %q, want the reviewed key", got)
	}
}

func TestReviewedGenerationRejectsAChangedDefinition(t *testing.T) {
	const keyType = "test.prepare-changed.v1"
	ir, _, _ := setupPrepareTest(t, keyType, "prepare-changed")
	service := Service{Runtime: ir}
	prepared, err := service.PrepareGenerateKey(keyType, map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference})
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}

	stale := "1:" + strings.Repeat("0", 64)
	_, err = service.GenerateReviewedKey(context.Background(), keyType, prepared.Parameters, ReviewedValues{Fingerprint: stale}, nil)
	if err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, "changed after this request was reviewed") {
		t.Fatalf("GenerateReviewedKey(stale) error = %#v", err)
	}
	assertNoKeys(t, service)

	// A direct request names no expected fingerprint and is judged on its own.
	if _, err := service.GenerateKey(context.Background(), keyType, prepared.Parameters, nil); err != nil {
		t.Fatalf("GenerateKey() error = %#v", err)
	}
}

func TestIPCServiceAppliesTheExpectedFingerprint(t *testing.T) {
	const keyType = "test.prepare-ipc.v1"
	ir, _, _ := setupPrepareTest(t, keyType, "prepare-ipc")
	service := IPCService{Service: Service{Runtime: ir}}
	prepared := service.PrepareGenerateKey(adminproto.PrepareGenerateKeyRequest{
		KeyType: keyType, Parameters: map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference},
	})
	if !prepared.Success || prepared.CosignerKeyID == "" || prepared.Bounded == nil || !prepared.Bounded.CosignerRequired {
		t.Fatalf("PrepareGenerateKey() = %+v", prepared)
	}
	stale := service.GenerateKey(context.Background(), adminproto.GenerateKeyRequest{
		KeyType: keyType, Parameters: prepared.Parameters, ExpectedFingerprint: "1:" + strings.Repeat("0", 64),
	})
	if stale.Success || !strings.Contains(stale.Error, "changed after this request was reviewed") {
		t.Fatalf("GenerateKey(stale) = %+v", stale)
	}
	current := service.GenerateKey(context.Background(), adminproto.GenerateKeyRequest{
		KeyType: keyType, Parameters: prepared.Parameters, ExpectedFingerprint: prepared.ReviewFingerprint,
	})
	if !current.Success {
		t.Fatalf("GenerateKey(current) = %+v", current)
	}
}

func TestPrepareGenerateKeyRefusesWhatGenerationRefuses(t *testing.T) {
	const keyType = "test.prepare-refuses.v1"
	ir, _, keyID := setupPrepareTest(t, keyType, "prepare-refuses")
	service := Service{Runtime: ir}

	for _, test := range []struct {
		name   string
		key    string
		params map[string]string
		want   string
	}{
		{name: "no key type", want: "key_type is required"},
		{name: "unknown reference", key: keyType, params: map[string]string{cosignerrefs.ParamCosignerName: "missing"}, want: "not found"},
		{name: "reference and raw key", key: keyType, params: map[string]string{
			cosignerrefs.ParamCosignerName:         prepareTestReference,
			boundedmeta.CosignerPublicKeyParameter: strings.Repeat("ab", falconfamily.PublicKeySize),
		}, want: "not both"},
		{name: "unknown key type", key: "test.prepare-missing.v1", want: "invalid key type"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, prepareErr := service.PrepareGenerateKey(test.key, test.params)
			if prepareErr == nil || prepareErr.Kind != ErrorInvalidInput || !strings.Contains(prepareErr.Message, test.want) {
				t.Fatalf("PrepareGenerateKey() error = %#v, want %q", prepareErr, test.want)
			}
			_, generateErr := service.GenerateKey(context.Background(), test.key, test.params, nil)
			if generateErr == nil || generateErr.Message != prepareErr.Message {
				t.Fatalf("GenerateKey() error = %#v, want the same as preparation %#v", generateErr, prepareErr)
			}
		})
	}

	t.Run("disabled key type", func(t *testing.T) {
		if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{
			KeyType: keyType, Source: keytypestate.SourceYAMLComposed, State: keytypestate.StateDisabled,
		}); err != nil {
			t.Fatal(err)
		}
		_, err := service.PrepareGenerateKey(keyType, map[string]string{cosignerrefs.ParamCosignerName: keyID})
		if err == nil || !strings.Contains(err.Message, "not enabled") {
			t.Fatalf("PrepareGenerateKey() error = %#v", err)
		}
	})
	assertNoKeys(t, service)
}

func TestPrepareGenerateKeyAcceptsAStableWitnessKeyID(t *testing.T) {
	const keyType = "test.prepare-witness-id.v1"
	ir, publicKey, keyID := setupPrepareTest(t, keyType, "prepare-witness-id")
	prepared, err := (Service{Runtime: ir}).PrepareGenerateKey(keyType, map[string]string{cosignerrefs.ParamCosignerName: keyID})
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	if got := prepared.Parameters[boundedmeta.CosignerPublicKeyParameter]; got != hex.EncodeToString(publicKey) {
		t.Fatalf("resolved public key = %q", got)
	}
}

func TestProjectPrepareGenerateIPC(t *testing.T) {
	result := ProjectPrepareGenerateIPC(&PreparedGeneration{
		KeyType: "test.projected.v1", Parameters: map[string]string{"recipients": "A"}, Fingerprint: "1:abc",
		CosignerKeyID: "COSIGNER",
		Warnings:      []string{"first warning", "second warning"},
		Bounded: &boundedmeta.Metadata{
			Contract: boundedmeta.Contract, SpendEffects: []string{"pay"}, MaxFee: new(uint64(10_000)),
			Layer3Policy: boundedmeta.Layer3PolicyMerkleAllowlist,
			Cosigner:     &boundedmeta.CosignerAuthorization{ComponentKeyType: witness.Falcon1024V1},
			Rekey:        boundedmeta.RekeyRefused,
		},
	}, nil)
	if !result.Success || result.Bounded == nil || !result.Bounded.CosignerRequired || result.Bounded.MaxFee == nil || *result.Bounded.MaxFee != 10_000 ||
		result.Bounded.Contract != boundedmeta.Contract || result.Bounded.Rekey != string(boundedmeta.RekeyRefused) ||
		result.Bounded.Layer3Policy != boundedmeta.Layer3PolicyMerkleAllowlist || result.CosignerKeyID != "COSIGNER" {
		t.Fatalf("result = %+v", result)
	}
	// The provider's warnings reach the reviewer in order; a result without any
	// carries none, and neither does a failure.
	if !slices.Equal(result.Warnings, []string{"first warning", "second warning"}) {
		t.Fatalf("Warnings = %q", result.Warnings)
	}
	if quiet := ProjectPrepareGenerateIPC(&PreparedGeneration{KeyType: "test.projected.v1"}, nil); !quiet.Success || len(quiet.Warnings) != 0 {
		t.Fatalf("a preparation without warnings projects %q", quiet.Warnings)
	}
	failed := ProjectPrepareGenerateIPC(nil, &Error{Kind: ErrorInvalidInput, Message: "bad request"})
	if failed.Success || failed.Error != "bad request" || failed.Code == "" || len(failed.Warnings) != 0 {
		t.Fatalf("failed = %+v", failed)
	}
}
