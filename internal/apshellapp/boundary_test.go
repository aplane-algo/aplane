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
		t.Fatalf("preview = %+v, want Witness Key ID %s", preview, id)
	}
}

func TestPreviewOfATimelockWithNoList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary.yaml")
	// A timelock takes a rekey-to list: a spending-key rekey would leave the lock early.
	target := types.Address{7}.String()
	if err := os.WriteFile(path, []byte("schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: only_these, to: ["+target+"]}\nunlock_round: 50000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := (&App{}).PreviewBoundaryFile(boundary.KeyTypeV1, path)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Recipients != 0 || preview.ListDigest != "" || preview.UnlockRound != "50000000" || preview.Rekey != boundary.RekeyOnlyThese || len(preview.RekeyTo) != 1 {
		t.Fatalf("preview = %+v", preview)
	}
	if _, present := preview.Parameters[boundary.ParameterRecipients]; present {
		t.Fatalf("parameters = %v", preview.Parameters)
	}
}

func TestPreviewOfALimitsOnlyAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boundary.yaml")
	if err := os.WriteFile(path, []byte("schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: spending_key}\nrecipient_scope: any\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	preview, err := (&App{}).PreviewBoundaryFile(boundary.KeyTypeV1, path)
	if err != nil {
		t.Fatal(err)
	}
	if !preview.AnyRecipient || preview.Recipients != 0 || preview.UnlockRound != "" {
		t.Fatalf("preview = %+v", preview)
	}
	if preview.Parameters[boundary.ParameterRecipientScope] != boundary.RecipientScopeAny {
		t.Fatalf("the scope must reach the signer: %v", preview.Parameters)
	}
}

func TestPreviewRejectsAnInvalidFile(t *testing.T) {
	if _, err := (&App{}).PreviewBoundaryFile(boundary.KeyTypeV1, writeBoundary(t, "teal: \"int 1\"\n")); err == nil {
		t.Fatal("a file carrying TEAL was accepted")
	}
}

func TestResultCarriesTheSignersAuthorityIDs(t *testing.T) {
	result := generateResultFromEngine(&engine.GenerateKeyResult{
		Address: "ADDRESS", KeyType: boundary.KeyTypeV1, CosignerKeyID: "COSIGNER",
	})
	if result.CosignerKeyID != "COSIGNER" {
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

// The file must not pass for a daemon-issued receipt, so it has no such fields.
func TestGenerationResultIsNotAReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	result := &GenerateKeyCommandResult{Address: "ADDRESS", KeyType: boundary.KeyTypeV1, Parameters: map[string]string{"recipients": "A"}, CosignerKeyID: "COSIGNER"}
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
	if fields["schema"] != GenerationResultSchemaV1 || fields["address"] != "ADDRESS" || fields["cosigner_key_id"] != "COSIGNER" {
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

// apshell's own options are flags, so a parameter named boundary or result is a
// signer parameter, sent on, and no lookup is needed to tell them apart.
func TestSplitGenerateOptions(t *testing.T) {
	options, rest, err := SplitGenerateOptions([]string{"recipients=A", "--boundary", "rules.yaml", "boundary=42", "--result=out.json"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.HasBoundaryFile || options.BoundaryFile != "rules.yaml" || options.ResultFile != "out.json" {
		t.Fatalf("options = %+v", options)
	}
	if len(rest) != 2 || rest[0] != "recipients=A" || rest[1] != "boundary=42" {
		t.Fatalf("rest = %v", rest)
	}
	options, rest, err = SplitGenerateOptions([]string{"other=1"})
	if err != nil || options != (GenerateOptions{}) || len(rest) != 1 {
		t.Fatalf("no flags: options = %+v, rest = %v, err = %v", options, rest, err)
	}
	for name, args := range map[string][]string{
		"unknown flag":       {"--boundry=rules.yaml"},
		"missing value":      {"--result"},
		"empty value":        {"--boundary="},
		"boundary twice":     {"--boundary=a", "--boundary=b"},
		"result given twice": {"--result=a", "--result", "b"},
		"flag as a value":    {"--result", "--boundary=corridor.yaml"},
	} {
		if _, _, err := SplitGenerateOptions(args); err == nil {
			t.Fatalf("%s: SplitGenerateOptions(%v) accepted it", name, args)
		}
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

func inventoryOf(infos ...signerapi.KeyTypeInfo) func() ([]signerapi.KeyTypeInfo, error) {
	return func() ([]signerapi.KeyTypeInfo, error) { return infos, nil }
}

// A boundary file goes only to a type the signer says takes one, canonicalized; a
// plain host, an unreported type or a failed lookup stops before the file is read.
func TestCheckBoundaryKeyType(t *testing.T) {
	bounded := signerapi.KeyTypeInfo{KeyType: "example.second-bounded.v1", PerKeyContract: true, BoundarySchema: boundary.SchemaV1}
	if err := checkBoundaryKeyType("  EXAMPLE.Second-Bounded.v1 ", inventoryOf(bounded)); err != nil {
		t.Fatal(err)
	}
	for name, inventory := range map[string]func() ([]signerapi.KeyTypeInfo, error){
		"lookup failed":        func() ([]signerapi.KeyTypeInfo, error) { return nil, errors.New("signer unavailable") },
		"type not in the list": inventoryOf(signerapi.KeyTypeInfo{KeyType: "falcon1024"}),
		"plain host":           inventoryOf(signerapi.KeyTypeInfo{KeyType: "example.second-bounded.v1", PerKeyContract: true}),
	} {
		if err := checkBoundaryKeyType(bounded.KeyType, inventory); err == nil {
			t.Fatalf("%s: checkBoundaryKeyType() accepted it", name)
		}
	}
}
