// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txeffects_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/txeffects"
)

type protocolInventory struct {
	Schema               string                     `json:"schema"`
	Contract             string                     `json:"contract"`
	TEALVersion          int                        `json:"teal_version"`
	GoAlgorandSDK        string                     `json:"go_algorand_sdk"`
	TransactionTypes     []inventoryTransactionType `json:"transaction_types"`
	SpendEffects         []string                   `json:"spend_effects"`
	AVMTxnFields         []string                   `json:"avm_txn_fields"`
	Classifications      map[string][]string        `json:"classifications"`
	SDKTransactionFields []string                   `json:"sdk_transaction_fields"`
}

type inventoryTransactionType struct {
	Name           string `json:"name"`
	Wire           string `json:"wire"`
	Classification string `json:"classification"`
}

func TestIndependentInventoryMatchesManifest(t *testing.T) {
	inventory := readProtocolInventory(t)
	if err := compareManifestToInventory(txeffects.Bounded1Manifest(), inventory); err != nil {
		t.Fatal(err)
	}
}

func TestIndependentInventoryDetectsEveryRemovedDangerPredicate(t *testing.T) {
	inventory := readProtocolInventory(t)
	manifest := txeffects.Bounded1Manifest()
	for i, predicate := range manifest.Predicates {
		t.Run(string(predicate.Field), func(t *testing.T) {
			mutated := txeffects.Bounded1Manifest()
			mutated.Predicates = append(mutated.Predicates[:i], mutated.Predicates[i+1:]...)
			if err := compareManifestToInventory(mutated, inventory); err == nil {
				t.Fatal("inventory comparison accepted a removed danger predicate")
			}
		})
	}
}

func TestIndependentInventoryClassifiesEveryAVMField(t *testing.T) {
	inventory := readProtocolInventory(t)
	known := stringSet(inventory.AVMTxnFields)
	classified := make(map[string]int)
	for class, fields := range inventory.Classifications {
		if len(fields) == 0 {
			t.Fatalf("classification %q is empty", class)
		}
		for _, field := range fields {
			if _, ok := known[field]; !ok {
				t.Errorf("classification %q contains unknown AVM field %q", class, field)
			}
			classified[field]++
		}
	}
	for _, field := range inventory.AVMTxnFields {
		if classified[field] == 0 {
			t.Errorf("AVM field %q has no classification", field)
		}
	}
}

func TestIndependentInventoryMatchesPinnedSDKSurface(t *testing.T) {
	inventory := readProtocolInventory(t)
	const pinnedSDK = "github.com/algorand/go-algorand-sdk/v2 v2.11.2-0.20260731180711-967fcacfacdf"
	if inventory.GoAlgorandSDK != pinnedSDK {
		t.Fatalf("go_algorand_sdk = %q, want %q", inventory.GoAlgorandSDK, pinnedSDK)
	}

	wantTypes := make([]string, 0, len(inventory.TransactionTypes))
	for _, entry := range inventory.TransactionTypes {
		wantTypes = append(wantTypes, entry.Wire)
	}
	assertSameStrings(t, "SDK transaction types", sdkTransactionTypes(t), wantTypes)
	assertSameStrings(t, "SDK transaction fields", sdkTransactionFields(), inventory.SDKTransactionFields)
}

func compareManifestToInventory(manifest txeffects.ContractManifest, inventory protocolInventory) error {
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("manifest validation: %w", err)
	}
	if inventory.Schema != "aplane.bounded-protocol-inventory.v1" {
		return fmt.Errorf("unexpected inventory schema %q", inventory.Schema)
	}
	if manifest.Contract != inventory.Contract || manifest.TEALVersion != inventory.TEALVersion {
		return fmt.Errorf("manifest contract/version %s/%d differs from inventory %s/%d", manifest.Contract, manifest.TEALVersion, inventory.Contract, inventory.TEALVersion)
	}

	manifestDanger := make([]string, 0, len(manifest.Predicates))
	for _, predicate := range manifest.Predicates {
		manifestDanger = append(manifestDanger, string(predicate.Field))
	}
	if diff := stringSetDiff(manifestDanger, inventory.Classifications["framework_danger_predicate"]); diff != "" {
		return fmt.Errorf("danger predicate mismatch: %s", diff)
	}

	var inventoryAllowed, inventoryDenied []string
	for _, entry := range inventory.TransactionTypes {
		switch entry.Classification {
		case "spend", "spend_or_rekey":
			inventoryAllowed = append(inventoryAllowed, entry.Wire)
		case "denied":
			inventoryDenied = append(inventoryDenied, entry.Wire)
		default:
			return fmt.Errorf("transaction type %q has unknown classification %q", entry.Name, entry.Classification)
		}
	}
	manifestEffects := spendEffectStrings(manifest.SpendEffects)
	if diff := stringSetDiff(manifestEffects, inventory.SpendEffects); diff != "" {
		return fmt.Errorf("spend effect mismatch: %s", diff)
	}
	var manifestAllowed []string
	for _, effect := range manifest.SpendEffects {
		switch effect {
		case txeffects.SpendEffectPay:
			manifestAllowed = append(manifestAllowed, string(types.PaymentTx))
		case txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn:
			manifestAllowed = append(manifestAllowed, string(types.AssetTransferTx))
		}
	}
	manifestDenied := txTypeStrings(manifest.KnownDeniedTypes)
	if diff := stringSetDiff(manifestAllowed, inventoryAllowed); diff != "" {
		return fmt.Errorf("allowed transaction type mismatch: %s", diff)
	}
	if diff := stringSetDiff(manifestDenied, inventoryDenied); diff != "" {
		return fmt.Errorf("denied transaction type mismatch: %s", diff)
	}
	return nil
}

func readProtocolInventory(t *testing.T) protocolInventory {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "BOUNDED1_PROTOCOL_INVENTORY.json"))
	if err != nil {
		t.Fatalf("read protocol inventory: %v", err)
	}
	var inventory protocolInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatalf("decode protocol inventory: %v", err)
	}
	return inventory
}

func sdkTransactionTypes(t *testing.T) []string {
	t.Helper()
	pc := reflect.ValueOf(types.DecodeAddress).Pointer()
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		t.Fatal("locate SDK DecodeAddress source")
	}
	file, _ := fn.FileLine(pc)
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(file), "basics.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse SDK basics.go: %v", err)
	}

	typesFound := []string{""}
	for _, declaration := range parsed.Decls {
		gen, ok := declaration.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok || len(valueSpec.Values) != 1 {
				continue
			}
			ident, ok := valueSpec.Type.(*ast.Ident)
			if !ok || ident.Name != "TxType" {
				continue
			}
			literal, ok := valueSpec.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			wire, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("decode SDK TxType constant: %v", err)
			}
			typesFound = append(typesFound, wire)
		}
	}
	return typesFound
}

func sdkTransactionFields() []string {
	var fields []string
	var walk func(reflect.Type)
	walk = func(value reflect.Type) {
		if value.Kind() == reflect.Pointer {
			value = value.Elem()
		}
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if field.Name == "_struct" {
				continue
			}
			fieldType := field.Type
			if fieldType.Kind() == reflect.Pointer {
				fieldType = fieldType.Elem()
			}
			if field.Anonymous && fieldType.Name() != "HeartbeatTxnFields" {
				walk(fieldType)
				continue
			}
			fields = append(fields, field.Name)
		}
	}
	walk(reflect.TypeOf(types.Transaction{}))
	return fields
}

func txTypeStrings(values []types.TxType) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func spendEffectStrings(values []txeffects.SpendEffect) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func stringSetDiff(left, right []string) string {
	leftSet := stringSet(left)
	rightSet := stringSet(right)
	var onlyLeft, onlyRight []string
	for value := range leftSet {
		if _, ok := rightSet[value]; !ok {
			onlyLeft = append(onlyLeft, value)
		}
	}
	for value := range rightSet {
		if _, ok := leftSet[value]; !ok {
			onlyRight = append(onlyRight, value)
		}
	}
	sort.Strings(onlyLeft)
	sort.Strings(onlyRight)
	if len(onlyLeft) == 0 && len(onlyRight) == 0 {
		return ""
	}
	return fmt.Sprintf("only left=%v, only right=%v", onlyLeft, onlyRight)
}

func assertSameStrings(t *testing.T, label string, got, want []string) {
	t.Helper()
	if diff := stringSetDiff(got, want); diff != "" {
		t.Fatalf("%s mismatch: %s; got=%v", label, diff, got)
	}
	if len(got) != len(stringSet(got)) || len(want) != len(stringSet(want)) {
		t.Fatalf("%s contains duplicate entries", label)
	}
}
