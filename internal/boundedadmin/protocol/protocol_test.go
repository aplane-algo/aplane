// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

func testRequestPayload() RequestPayload {
	return RequestPayload{
		Network:            "localnet",
		GenesisHashHex:     strings.Repeat("11", 32),
		CurrentAuthAddress: "AUTH",
		Partial: signerapi.BoundedAdminPartialResponse{
			Schema:        signerapi.BoundedAdminPartialSchemaV1,
			Operation:     signerapi.BoundedAdminOperationRekey,
			Transactions:  []string{"aa"},
			PartialSigned: []string{"bb"},
			Authorization: signerapi.BoundedAdminMetadata{
				ContractAdminKeyID:     "ADMIN",
				PublicKeyHex:           "cc",
				SpendingPublicKeyHex:   "dd",
				ProgramBindingHex:      "ee",
				TransactionID:          "TXID",
				MessageHex:             "ff",
				BaseSignatureArgCount:  1,
				AdminSignatureArgIndex: 1,
				SpendEffects:           []string{"pay", "axfer"},
				MaxFee:                 10_000,
			},
			Mutations: &signerapi.MutationReport{
				DummiesAdded: 2, GroupIDChanged: true, FeesModified: []int{0}, TotalFeesDelta: 2_000,
				OriginalCount: 1, FinalCount: 3, PassthroughCount: 1, ForeignCount: 1, Reason: "lsig_budget",
			},
		},
	}
}

func TestRequestHashBindsEveryField(t *testing.T) {
	base := testRequestPayload()
	want, err := RequestHash(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*RequestPayload)
	}{
		{name: "network", mutate: func(value *RequestPayload) { value.Network += "x" }},
		{name: "genesis hash", mutate: func(value *RequestPayload) { value.GenesisHashHex += "00" }},
		{name: "current auth", mutate: func(value *RequestPayload) { value.CurrentAuthAddress += "X" }},
		{name: "partial schema", mutate: func(value *RequestPayload) { value.Partial.Schema += "x" }},
		{name: "operation", mutate: func(value *RequestPayload) { value.Partial.Operation = "close" }},
		{name: "transactions", mutate: func(value *RequestPayload) { value.Partial.Transactions = append(value.Partial.Transactions, "ab") }},
		{name: "partial signed", mutate: func(value *RequestPayload) { value.Partial.PartialSigned = append(value.Partial.PartialSigned, "bc") }},
		{name: "target index", mutate: func(value *RequestPayload) { value.Partial.TargetIndex++ }},
		{name: "admin key id", mutate: func(value *RequestPayload) { value.Partial.Authorization.ContractAdminKeyID += "X" }},
		{name: "admin public key", mutate: func(value *RequestPayload) { value.Partial.Authorization.PublicKeyHex += "00" }},
		{name: "spending public key", mutate: func(value *RequestPayload) { value.Partial.Authorization.SpendingPublicKeyHex += "00" }},
		{name: "program binding", mutate: func(value *RequestPayload) { value.Partial.Authorization.ProgramBindingHex += "00" }},
		{name: "transaction id", mutate: func(value *RequestPayload) { value.Partial.Authorization.TransactionID += "X" }},
		{name: "message", mutate: func(value *RequestPayload) { value.Partial.Authorization.MessageHex += "00" }},
		{name: "base arg count", mutate: func(value *RequestPayload) { value.Partial.Authorization.BaseSignatureArgCount++ }},
		{name: "admin arg index", mutate: func(value *RequestPayload) { value.Partial.Authorization.AdminSignatureArgIndex++ }},
		{name: "spend effects", mutate: func(value *RequestPayload) { value.Partial.Authorization.SpendEffects = []string{"pay"} }},
		{name: "max fee", mutate: func(value *RequestPayload) { value.Partial.Authorization.MaxFee-- }},
		{name: "mutation presence", mutate: func(value *RequestPayload) { value.Partial.Mutations = nil }},
		{name: "dummies added", mutate: func(value *RequestPayload) { value.Partial.Mutations.DummiesAdded++ }},
		{name: "group changed", mutate: func(value *RequestPayload) { value.Partial.Mutations.GroupIDChanged = false }},
		{name: "fees modified", mutate: func(value *RequestPayload) {
			value.Partial.Mutations.FeesModified = append(value.Partial.Mutations.FeesModified, 1)
		}},
		{name: "fee delta", mutate: func(value *RequestPayload) { value.Partial.Mutations.TotalFeesDelta++ }},
		{name: "original count", mutate: func(value *RequestPayload) { value.Partial.Mutations.OriginalCount++ }},
		{name: "final count", mutate: func(value *RequestPayload) { value.Partial.Mutations.FinalCount++ }},
		{name: "passthrough count", mutate: func(value *RequestPayload) { value.Partial.Mutations.PassthroughCount++ }},
		{name: "foreign count", mutate: func(value *RequestPayload) { value.Partial.Mutations.ForeignCount++ }},
		{name: "mutation reason", mutate: func(value *RequestPayload) { value.Partial.Mutations.Reason += "x" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			value := testRequestPayload()
			mutation.mutate(&value)
			got, err := RequestHash(value)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("mutation did not change request hash")
			}
		})
	}
}

func TestRequestHashFieldInventory(t *testing.T) {
	for name, check := range map[string]struct {
		value any
		want  int
	}{
		"request payload": {value: RequestPayload{}, want: 4},
		"partial":         {value: signerapi.BoundedAdminPartialResponse{}, want: 7},
		"authorization":   {value: signerapi.BoundedAdminMetadata{}, want: 10},
		"mutation report": {value: signerapi.MutationReport{}, want: 9},
	} {
		if got := reflect.TypeOf(check.value).NumField(); got != check.want {
			t.Fatalf("%s field count = %d, want %d; update RequestHash and its mutation tests", name, got, check.want)
		}
	}
}

func TestRequestHashGolden(t *testing.T) {
	got, err := RequestHash(testRequestPayload())
	if err != nil {
		t.Fatal(err)
	}
	const want = "94280ecc570ad13e0ca8592fa00406298eb64a6c9903d111b09316dd61dee078"
	if value := fmt.Sprintf("%x", got); value != want {
		t.Fatalf("RequestHash() = %s, want %s", value, want)
	}
}

func TestValidateRequestRejectsObsoleteSchema(t *testing.T) {
	err := ValidateEnvelope(Request{Schema: "aplane.governed-rekey-request.v1"})
	if ErrorCode(err) != ErrorUnsupportedRequestSchema {
		t.Fatalf("ErrorCode() = %q, want %q", ErrorCode(err), ErrorUnsupportedRequestSchema)
	}
}

func TestDecodeRequestAndResponseAreStrictAndBounded(t *testing.T) {
	if _, err := DecodeRequest(strings.NewReader(`{"schema":"aplane.bounded-admin-request.v1","unknown":true}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeRequest() error = %v, want unknown-field rejection", err)
	}
	if _, err := DecodeResponse(bytes.NewReader(make([]byte, MaxResponseBytes+1))); err == nil {
		t.Fatal("DecodeResponse() accepted oversized input")
	}
}

func TestProtocolErrorUnwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &Error{Code: ErrorUnsupportedRequestSchema, Err: inner}
	if !errors.Is(err, inner) {
		t.Fatal("Error does not unwrap its cause")
	}
}
