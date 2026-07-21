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
		{name: "htlc", file: "aplane.htlc.v1.yaml", want: "1:d0fb70ab0540fc66d3aac6b7ef804f6cabf301fbcacbd2b2f983e5a1cb53ffce"},
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
	const want = "1:328eede0d895c241594ca3809dd9209e418b30e0e1bd87dc5b2900369d6f8322"
	if got != want {
		t.Fatalf("SemanticFingerprint(synthetic) = %q, want %q", got, want)
	}
}
