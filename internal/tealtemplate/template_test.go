// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tealtemplate

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestRenderStrictGeneratesDeterministicConstantBlocks(t *testing.T) {
	var recipient types.Address
	recipient[31] = 1

	rendered, err := RenderStrict(`#pragma version 10
txn Receiver
$recipient
==
assert
txn FirstValid
$unlock_round
>=
assert`, map[string]string{
		"unlock_round": "42",
		"recipient":    recipient.String(),
	}, []TemplateVariable{
		{
			Name:      "recipient",
			Source:    SourceParameter,
			Parameter: "recipient",
			Type:      "address",
			Constant:  ConstantByte,
		},
		{
			Name:      "unlock_round",
			Source:    SourceParameter,
			Parameter: "unlock_round",
			Type:      "uint64",
			Constant:  ConstantInt,
		},
	})
	if err != nil {
		t.Fatalf("RenderStrict returned error: %v", err)
	}

	wantTEAL := `#pragma version 10
intcblock 42
bytecblock 0x0000000000000000000000000000000000000000000000000000000000000001

txn Receiver
bytec_0
==
assert
txn FirstValid
intc_0
>=
assert`
	if rendered.TEAL != wantTEAL {
		t.Fatalf("unexpected rendered TEAL:\n%s", rendered.TEAL)
	}
	if got := rendered.ByteSlots[0].Name; got != "recipient" {
		t.Fatalf("byte slot name = %q, want recipient", got)
	}
	if got := rendered.IntSlots[0].Name; got != "unlock_round" {
		t.Fatalf("int slot name = %q, want unlock_round", got)
	}
}

func TestRenderStrictNormalizesBytesAndUint64(t *testing.T) {
	rendered, err := RenderStrict(`$threshold
$payload`, map[string]string{
		"threshold": "0007",
		"payload":   "0XABCD",
	}, []TemplateVariable{
		{
			Name:      "threshold",
			Source:    SourceParameter,
			Parameter: "threshold",
			Type:      "uint64",
			Constant:  ConstantInt,
		},
		{
			Name:      "payload",
			Source:    SourceParameter,
			Parameter: "payload",
			Type:      "bytes",
			Constant:  ConstantByte,
		},
	})
	if err != nil {
		t.Fatalf("RenderStrict returned error: %v", err)
	}

	if !strings.HasPrefix(rendered.TEAL, "intcblock 7\nbytecblock 0xabcd\n\n") {
		t.Fatalf("unexpected constant block prefix:\n%s", rendered.TEAL)
	}
}

func TestRenderStrictFragmentSeparatesBlocksFromBody(t *testing.T) {
	rendered, err := RenderStrictFragment("$payload", map[string]string{
		"payload": "abcd",
	}, []TemplateVariable{
		{
			Name:      "payload",
			Source:    SourceParameter,
			Parameter: "payload",
			Type:      "bytes",
			Constant:  ConstantByte,
		},
	})
	if err != nil {
		t.Fatalf("RenderStrictFragment returned error: %v", err)
	}

	if rendered.ConstantBlocks != "bytecblock 0xabcd" {
		t.Fatalf("ConstantBlocks = %q, want bytecblock 0xabcd", rendered.ConstantBlocks)
	}
	if rendered.TEAL != "bytec_0" {
		t.Fatalf("TEAL = %q, want bytec_0", rendered.TEAL)
	}
}

func TestRenderStrictRejectsLegacyScalarSubstitution(t *testing.T) {
	_, err := RenderStrict("txn Receiver\n@recipient\n==", map[string]string{}, nil)
	if err == nil || !strings.Contains(err.Error(), "legacy scalar substitution") {
		t.Fatalf("expected legacy scalar substitution error, got %v", err)
	}
}

func TestRenderStrictRejectsGeneratedTemplateSyntax(t *testing.T) {
	_, err := RenderStrict("{{range recipients}}\nbyte {{.}}\n{{end}}", map[string]string{}, nil)
	if err == nil || !strings.Contains(err.Error(), "generated template syntax") {
		t.Fatalf("expected generated template syntax error, got %v", err)
	}
}

func TestRenderStrictRejectsUndeclaredSymbol(t *testing.T) {
	_, err := RenderStrict("$recipient", map[string]string{}, nil)
	if err == nil || !strings.Contains(err.Error(), "undeclared variable") {
		t.Fatalf("expected undeclared variable error, got %v", err)
	}
}

func TestRenderStrictRejectsUnusedDeclaration(t *testing.T) {
	_, err := RenderStrict("int 1", map[string]string{
		"recipient": "abcd",
	}, []TemplateVariable{
		{
			Name:      "recipient",
			Source:    SourceParameter,
			Parameter: "recipient",
			Type:      "bytes",
			Constant:  ConstantByte,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "declared but not referenced") {
		t.Fatalf("expected unused declaration error, got %v", err)
	}
}

func TestRenderStrictRejectsConstantTypeMismatch(t *testing.T) {
	_, err := RenderStrict("$unlock_round", map[string]string{
		"unlock_round": "42",
	}, []TemplateVariable{
		{
			Name:      "unlock_round",
			Source:    SourceParameter,
			Parameter: "unlock_round",
			Type:      "uint64",
			Constant:  ConstantByte,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must use int constants") {
		t.Fatalf("expected constant type mismatch error, got %v", err)
	}
}

func TestRenderStrictRejectsUnsupportedListType(t *testing.T) {
	_, err := RenderStrict("$asset_ids", map[string]string{
		"asset_ids": "1,2",
	}, []TemplateVariable{
		{
			Name:      "asset_ids",
			Source:    SourceParameter,
			Parameter: "asset_ids",
			Type:      "uint64[]",
			Constant:  ConstantByte,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func TestRenderStrictRequiresParameterValue(t *testing.T) {
	_, err := RenderStrict("$recipient", map[string]string{}, []TemplateVariable{
		{
			Name:      "recipient",
			Source:    SourceParameter,
			Parameter: "recipient",
			Type:      "bytes",
			Constant:  ConstantByte,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "missing template parameter") {
		t.Fatalf("expected missing template parameter error, got %v", err)
	}
}

func TestRenderStrictRejectsUnsupportedSource(t *testing.T) {
	_, err := RenderStrict("$recipient", map[string]string{
		"recipient": "abcd",
	}, []TemplateVariable{
		{
			Name:      "recipient",
			Source:    "runtime_arg",
			Parameter: "recipient",
			Type:      "bytes",
			Constant:  ConstantByte,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported source") {
		t.Fatalf("expected unsupported source error, got %v", err)
	}
}
