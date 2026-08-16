// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package generictemplate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundledGenericTemplateCompatibilityFingerprints(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{name: "htlc", file: "aplane.htlc.v1.yaml", want: "1:761ae862adaa3af2860ba4b9d5ba54b535db070000d261a1a4e56c9d7b17411e"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", tc.file))
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", tc.file, err)
			}
			got, err := SemanticFingerprint(data)
			if err != nil {
				t.Fatalf("SemanticFingerprint(%s) error = %v", tc.file, err)
			}
			if got != tc.want {
				t.Fatalf("SemanticFingerprint(%s) = %q, want %q", tc.file, got, tc.want)
			}
		})
	}
}

func TestSyntheticGenericTemplateCompatibilityFingerprint(t *testing.T) {
	const yamlData = `
schema_version: 1
template_mode: strict
publisher: test
family: synthetic-generic
version: 7
display_name: "Synthetic Generic"
description: "Exercises every canonical fingerprint field"
max_opcode_cost: 20000
parameters:
  - name: owner
    type: address
    required: true
  - name: hash
    type: bytes
    required: true
    max_length: 64
  - name: unlock_round
    type: uint64
    required: false
    max_length: 20
    min: 1
    max: 999
    default: "100"
  - name: recipients
    type: address[]
    required: false
    min_items: 1
    max_items: 3
template_variables:
  - name: owner_const
    source: parameter
    parameter: owner
    type: address
    constant: byte
  - name: unlock_round_const
    source: parameter
    parameter: unlock_round
    type: uint64
    constant: int
runtime_args:
  - name: preimage
    type: bytes
    required: true
    byte_length: 32
  - name: note
    type: string
    required: false
teal: |
  $owner_const
  len
  int 32
  ==
  assert
  txn FirstValid
  $unlock_round_const
  >=
  assert
  int 1
  return
`

	got, err := SemanticFingerprint([]byte(yamlData))
	if err != nil {
		t.Fatalf("SemanticFingerprint(synthetic) error = %v", err)
	}
	const want = "1:56662af43842a4d57dc202b53605aa1d8a0d3e66a9c2254ecb47eb2211f5e7bc"
	if got != want {
		t.Fatalf("SemanticFingerprint(synthetic) = %q, want %q", got, want)
	}
}
