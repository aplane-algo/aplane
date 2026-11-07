// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func writeBoundary(t *testing.T, extra string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "boundary.yaml")
	recipient := types.Address{31: 7}.String()
	body := "schema: aplane.boundary.v1\nspend: [pay]\nrecipients: [" + recipient + "]\nrekey: {authority: spending_key}\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func witnessIDFor(t *testing.T, fill byte) (string, string) {
	t.Helper()
	publicKey := bytes.Repeat([]byte{fill}, witness.Falcon1024PublicKeySize)
	id, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return id, hex.EncodeToString(publicKey)
}

func TestPreviewSummarizesTheFileWithoutResolvingAnything(t *testing.T) {
	preview, err := (&App{}).PreviewBoundaryFile(boundary.KeyTypeV1, writeBoundary(t, "cosigner: ops-cosigner\n"))
	if err != nil {
		t.Fatal(err)
	}
	if preview.Recipients != 1 || preview.Encoding != boundary.EncodingAuto || strings.Join(preview.Transfers, ",") != "pay" {
		t.Fatalf("preview = %+v", preview)
	}
	if preview.Cosigner != "ops-cosigner" || preview.CosignerIsKey {
		t.Fatalf("a reference name was treated as a key: %+v", preview)
	}
	if preview.Parameters[boundary.ParameterCosigner] != "ops-cosigner" {
		t.Fatalf("the name must reach the signer unresolved: %v", preview.Parameters)
	}
	if _, present := preview.Parameters[boundedmeta.CosignerPublicKeyParameter]; present {
		t.Fatal("apshell resolved a cosigner locally")
	}
}

func TestPreviewRecognizesAStableWitnessKeyID(t *testing.T) {
	id, _ := witnessIDFor(t, 0x61)
	preview, err := (&App{}).PreviewBoundaryFile(boundary.KeyTypeV1, writeBoundary(t, "cosigner: "+id+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !preview.CosignerIsKey || preview.Cosigner != id {
		t.Fatalf("preview = %+v, want Cosigner Key ID %s", preview, id)
	}
}

func TestPreviewOfATimelockWithNoList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary.yaml")
	if err := os.WriteFile(path, []byte("schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: spending_key}\nunlock_round: 50000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := (&App{}).PreviewBoundaryFile(boundary.KeyTypeV1, path)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Recipients != 0 || preview.ListDigest != "" || preview.UnlockRound != "50000000" {
		t.Fatalf("preview = %+v", preview)
	}
	if _, present := preview.Parameters[boundary.ParameterRecipients]; present {
		t.Fatalf("parameters = %v", preview.Parameters)
	}
}

func TestPreviewRejectsAnInvalidFile(t *testing.T) {
	if _, err := (&App{}).PreviewBoundaryFile(boundary.KeyTypeV1, writeBoundary(t, "teal: \"int 1\"\n")); err == nil {
		t.Fatal("a file carrying TEAL was accepted")
	}
}

func TestResultCarriesTheSignersAuthorityIDs(t *testing.T) {
	result := generateResultFromEngine(&engine.GenerateKeyResult{
		Address: "ADDRESS", KeyType: boundary.KeyTypeV1, AdminKeyID: "ADMIN", CosignerKeyID: "COSIGNER",
	})
	if result.AdminKeyID != "ADMIN" || result.CosignerKeyID != "COSIGNER" {
		t.Fatalf("result = %+v", result)
	}
}

// A stable ID exists so the operator knows which authority was used, so an account
// that cannot be shown to use it is an error, not a success with a blank field.
func TestRequestedCosignerMustBeConfirmed(t *testing.T) {
	for _, test := range []struct {
		name   string
		result engine.GenerateKeyResult
		want   string
	}{
		{"matches", engine.GenerateKeyResult{Address: "A", CosignerKeyID: "WANTED", InventoryRead: true}, ""},
		{"different authority", engine.GenerateKeyResult{Address: "A", CosignerKeyID: "OTHER", InventoryRead: true}, "do not fund"},
		{"no cosigner", engine.GenerateKeyResult{Address: "A", InventoryRead: true}, "do not fund"},
		{"inventory unreadable", engine.GenerateKeyResult{Address: "A"}, "could not read it back"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := confirmCosigner(&test.result, "WANTED")
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("confirmCosigner() error = %v", err)
			}
		})
	}
}

func TestPreviewIdentifiesTheAdminKey(t *testing.T) {
	id, publicKey := witnessIDFor(t, 0x71)
	got, err := boundary.AdminKeyID(map[string]string{boundedmeta.AdminPublicKeyParameter: publicKey})
	if err != nil || got != id {
		t.Fatalf("AdminKeyID() = %q, %v, want %s", got, err, id)
	}
	if got, err := boundary.AdminKeyID(nil); err != nil || got != "" {
		t.Fatalf("no admin key = %q, %v", got, err)
	}
}

// The file must not pass for a daemon-issued receipt, so it has no such fields.
func TestGenerationResultIsNotAReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	result := &GenerateKeyCommandResult{Address: "ADDRESS", KeyType: boundary.KeyTypeV1, Parameters: map[string]string{"recipients": "A"}, AdminKeyID: "ADMIN"}
	if err := WriteGenerationResult(path, result); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["schema"] != GenerationResultSchemaV1 || fields["address"] != "ADDRESS" || fields["admin_key_id"] != "ADMIN" {
		t.Fatalf("fields = %v", fields)
	}
	for _, name := range []string{"boundary_digest", "grammar_fingerprint", "selected_shape_fingerprint"} {
		if _, present := fields[name]; present {
			t.Fatalf("apshell invented %s", name)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	if err := WriteGenerationResult(path, result); err == nil {
		t.Fatal("overwrote an existing result")
	}
}

func inventoryOf(infos ...signerapi.KeyTypeInfo) func() ([]signerapi.KeyTypeInfo, error) {
	return func() ([]signerapi.KeyTypeInfo, error) { return infos, nil }
}

// A template may declare a parameter called boundary or result, so apshell must not
// take them from a type the signer doesn't report as per-key.
func TestGenerateOptionsLeaveOtherTypesAlone(t *testing.T) {
	for _, keyType := range []string{"test.custom-template.v1", "aplane.htlc.v1", "falcon1024"} {
		params := map[string]string{GenerateOptionBoundaryFile: "42", GenerateOptionResultFile: "43", "other": "1"}
		// An older signer omits the field, and has no per-key types to miss.
		options, err := takeGenerateOptions(keyType, params, inventoryOf(signerapi.KeyTypeInfo{KeyType: keyType}))
		if err != nil {
			t.Fatalf("%s: %v", keyType, err)
		}
		if options != (GenerateOptions{}) {
			t.Fatalf("%s: options = %+v", keyType, options)
		}
		if params[GenerateOptionBoundaryFile] != "42" || params[GenerateOptionResultFile] != "43" || len(params) != 3 {
			t.Fatalf("%s: parameters were changed: %v", keyType, params)
		}
	}
}

func TestGenerateOptionsFollowTheInventoryNotAName(t *testing.T) {
	for _, keyType := range []string{boundary.KeyTypeV1, "example.second-bounded.v1"} {
		inventory := inventoryOf(signerapi.KeyTypeInfo{KeyType: keyType, PerKeyContract: true})
		params := map[string]string{GenerateOptionBoundaryFile: "rules.yaml", GenerateOptionResultFile: "out.json"}
		options, err := takeGenerateOptions(keyType, params, inventory)
		if err != nil {
			t.Fatal(err)
		}
		if !options.HasBoundaryFile || options.BoundaryFile != "rules.yaml" || options.ResultFile != "out.json" {
			t.Fatalf("%s: options = %+v", keyType, options)
		}
		if len(params) != 0 {
			t.Fatalf("%s: options would reach the signer: %v", keyType, params)
		}

		params = map[string]string{GenerateOptionResultFile: "out.json", boundary.ParameterRecipients: "A"}
		options, err = takeGenerateOptions(keyType, params, inventory)
		if err != nil {
			t.Fatal(err)
		}
		if options.HasBoundaryFile || options.ResultFile != "out.json" || len(params) != 1 {
			t.Fatalf("%s: options = %+v, params = %v", keyType, options, params)
		}
	}
}

func TestGenerateOptionsCanonicalizeTheSelection(t *testing.T) {
	params := map[string]string{GenerateOptionResultFile: "out.json"}
	inventory := inventoryOf(signerapi.KeyTypeInfo{KeyType: "example.second-bounded.v1", PerKeyContract: true})
	options, err := takeGenerateOptions("  EXAMPLE.Second-Bounded.v1 ", params, inventory)
	if err != nil || options.ResultFile != "out.json" {
		t.Fatalf("options = %+v, err = %v", options, err)
	}
}

// The bounded type's name is no longer enough, so a lookup that doesn't answer must
// stop before either name is interpreted or forwarded.
func TestFailedDiscoveryInterpretsNothing(t *testing.T) {
	for name, inventory := range map[string]func() ([]signerapi.KeyTypeInfo, error){
		"lookup failed":        func() ([]signerapi.KeyTypeInfo, error) { return nil, errors.New("signer unavailable") },
		"empty inventory":      inventoryOf(),
		"type not in the list": inventoryOf(signerapi.KeyTypeInfo{KeyType: "falcon1024"}),
	} {
		t.Run(name, func(t *testing.T) {
			params := map[string]string{GenerateOptionBoundaryFile: "rules.yaml", GenerateOptionResultFile: "out.json"}
			options, err := takeGenerateOptions(boundary.KeyTypeV1, params, inventory)
			if err == nil {
				t.Fatal("takeGenerateOptions() error = nil")
			}
			if options != (GenerateOptions{}) || len(params) != 2 {
				t.Fatalf("options = %+v, params = %v", options, params)
			}
		})
	}
}

// Without either name there is nothing to tell apart, so ordinary generation gains no
// dependency on a lookup.
func TestGenerateWithoutOptionsNeedsNoLookup(t *testing.T) {
	params := map[string]string{"other": "1"}
	options, err := takeGenerateOptions("falcon1024", params, func() ([]signerapi.KeyTypeInfo, error) {
		t.Fatal("looked up inventory with nothing to interpret")
		return nil, nil
	})
	if err != nil || options != (GenerateOptions{}) || len(params) != 1 {
		t.Fatalf("options = %+v, params = %v, err = %v", options, params, err)
	}
}

func TestPreviewCarriesTheClassifiedKeyType(t *testing.T) {
	preview, err := (&App{}).PreviewBoundaryFile("example.second-bounded.v1", writeBoundary(t, "cosigner: ops-cosigner\n"))
	if err != nil {
		t.Fatal(err)
	}
	if preview.KeyType != "example.second-bounded.v1" {
		t.Fatalf("KeyType = %q", preview.KeyType)
	}
}
