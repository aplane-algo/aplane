// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"testing"

	"github.com/aplane-algo/aplane/lsig/generictemplate"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// Install admits a description written as a YAML block scalar, whose text
// ends with a line break, and stores the YAML as written. The key-type list
// gives clients the description without that break.
func TestKeyTypeListDropsTheBlockScalarLineBreak(t *testing.T) {
	spec, err := generictemplate.ParseTemplateSpec([]byte(`schema_version: 1
derivation_version: 3
template_mode: generated
publisher: test
family: block-description
version: 1
display_name: "Block Description"
description: |
  Pays one recipient
valid_rekey_target: false
max_opcode_cost: 20000
parameters:
  - name: note
    label: "Note"
    description: >
      A note for
      the operator
    type: string
runtime_args:
  - name: secret
    label: "Secret"
    description: |
      The secret
    type: bytes
    max_size: 32
teal: |
  #pragma version 8
  int 1
  return
`))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	var info signerapi.KeyTypeInfo
	describeProvider(&info, generictemplate.NewYAMLTemplate(spec))
	if info.Description != "Pays one recipient" {
		t.Fatalf("description = %q", info.Description)
	}
	if len(info.CreationParams) != 1 || info.CreationParams[0].Description != "A note for the operator" {
		t.Fatalf("parameters = %+v", info.CreationParams)
	}
	if len(info.RuntimeArgs) != 1 || info.RuntimeArgs[0].Description != "The secret" {
		t.Fatalf("runtime arguments = %+v", info.RuntimeArgs)
	}
}
