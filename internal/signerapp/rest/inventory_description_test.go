// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signingargs"
	"github.com/aplane-algo/aplane/internal/templatespec"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

const blockDescriptionGenericYAML = `schema_version: 1
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
  - name: limit
    label: "Limit"
    description: >
      A limit for
      the operator
    type: uint64
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
`

const blockDescriptionComposedYAML = `schema_version: 2
derivation_version: 3
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: block-description-bounded
version: 1
display_name: "Block Description Bounded"
description: |
  Pays with a preimage
valid_rekey_target: true
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: spending_key
  runtime_args:
    - name: preimage
      label: "Preimage"
      description: |
        The preimage
      type: bytes
      max_size: 64
      required_on: [spend]
teal: |
  int 1
  assert
`

// Install admits a description written as a YAML block scalar, whose text
// ends with a line break, and stores the YAML as written, so the provider an
// enabled template registers keeps the break, and so does the signing
// metadata of an aplane key made from it. Every listing gives clients each
// description without it: /keytypes for an enabled generic template and for
// a composed one, its bounded contract included, and /keys for the accounts
// made from them.
func TestKeyTypeListingsDropTheBlockScalarLineBreak(t *testing.T) {
	falcon.RegisterClient()
	ir := setupProductRuntime(t, true)

	genericSpec, err := generictemplate.ParseTemplateSpec([]byte(blockDescriptionGenericYAML))
	if err != nil {
		t.Fatalf("ParseTemplateSpec(generic) error = %v", err)
	}
	generic := generictemplate.NewYAMLTemplate(genericSpec)
	lsigprovider.RegisterIfAbsent(generic)
	t.Cleanup(func() { lsigprovider.Unregister(generic.KeyType()) })
	writeTemplateStateForRestTest(t, ir.KeyPaths(), generic.KeyType(), templatespec.TemplateTypeGeneric, keytypestate.StateEnabled)

	composedSpec, err := composeddsa.ParseTemplateSpec([]byte(blockDescriptionComposedYAML))
	if err != nil {
		t.Fatalf("ParseTemplateSpec(composed) error = %v", err)
	}
	composed, err := composeddsa.NewProviderFromTemplateSpec(composedSpec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	logicsigdsa.RegisterIfAbsent(composed)
	t.Cleanup(func() { lsigprovider.Unregister(composed.KeyType()) })
	writeTemplateStateForRestTest(t, ir.KeyPaths(), composed.KeyType(), templatespec.TemplateTypeComposed, keytypestate.StateEnabled)

	genericKey := keys.NewGenericLSigPayload(generic.KeyType(), map[string]string{"limit": "1"}, []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}, "",
		signingargs.FromRuntimeDefs(generic.RuntimeArgs()), "")
	if err := genericKey.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); err != nil {
		t.Fatal(err)
	}
	boundedKey := keys.NewDSALSigPayload(composed.KeyType(), "aplane.falcon1024.v1", bytes.Repeat([]byte{1}, 1793), bytes.Repeat([]byte{2}, 2305), nil,
		[]byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x02}, "", nil, "")
	if err := boundedKey.SetLogicSigOpcodeProfile(composed.LogicSigOpcodeProfile(), true); err != nil {
		t.Fatal(err)
	}
	if err := boundedKey.SetHost(composed.HostMetadata()); err != nil {
		t.Fatal(err)
	}
	saveAndReload(t, ir, genericKey, boundedKey)

	keyTypes, svcErr := Service{}.KeyTypes(ir)
	if svcErr != nil {
		t.Fatalf("KeyTypes() error = %v", svcErr)
	}
	byType := make(map[string]signerapi.KeyTypeInfo)
	for _, info := range keyTypes.KeyTypes {
		byType[info.KeyType] = info
	}
	genericInfo, ok := byType[generic.KeyType()]
	if !ok {
		t.Fatalf("KeyTypes() does not list %s", generic.KeyType())
	}
	if genericInfo.Description != "Pays one recipient" {
		t.Fatalf("generic description = %q", genericInfo.Description)
	}
	if len(genericInfo.CreationParams) != 1 || genericInfo.CreationParams[0].Description != "A limit for the operator" {
		t.Fatalf("generic parameters = %+v", genericInfo.CreationParams)
	}
	if len(genericInfo.RuntimeArgs) != 1 || genericInfo.RuntimeArgs[0].Description != "The secret" {
		t.Fatalf("generic runtime arguments = %+v", genericInfo.RuntimeArgs)
	}
	composedInfo, ok := byType[composed.KeyType()]
	if !ok {
		t.Fatalf("KeyTypes() does not list %s", composed.KeyType())
	}
	if composedInfo.Description != "Pays with a preimage" {
		t.Fatalf("composed description = %q", composedInfo.Description)
	}
	if len(composedInfo.RuntimeArgs) != 1 || composedInfo.RuntimeArgs[0].Description != "The preimage" {
		t.Fatalf("composed runtime arguments = %+v", composedInfo.RuntimeArgs)
	}
	if bounded := composedInfo.Host; bounded == nil || len(bounded.RuntimeArgs) != 1 || bounded.RuntimeArgs[0].Description != "The preimage" {
		t.Fatalf("composed bounded authorization = %+v", bounded)
	}
	assertNoLineBreak(t, "/keytypes", []signerapi.KeyTypeInfo{genericInfo, composedInfo})

	listed, svcErr := Service{}.Keys(ir)
	if svcErr != nil {
		t.Fatalf("Keys() error = %v", svcErr)
	}
	if len(listed.Keys) != 2 {
		t.Fatalf("Keys() returned %d keys, want 2", len(listed.Keys))
	}
	for _, key := range listed.Keys {
		switch key.KeyType {
		case generic.KeyType():
			if len(key.SigningArgs) != 1 || key.SigningArgs[0].Description != "The secret" {
				t.Fatalf("generic key signing arguments = %+v", key.SigningArgs)
			}
		case composed.KeyType():
			if bounded := key.Host; bounded == nil || len(bounded.RuntimeArgs) != 1 || bounded.RuntimeArgs[0].Description != "The preimage" {
				t.Fatalf("bounded key authorization = %+v", bounded)
			}
		default:
			t.Fatalf("Keys() listed %s", key.KeyType)
		}
	}
	assertNoLineBreak(t, "/keys", listed)
}

func saveAndReload(t *testing.T, ir *productruntime.Runtime, payloads ...*keys.Payload) {
	t.Helper()
	if err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		for _, payload := range payloads {
			if _, err := keys.SaveNewPayload(ir.KeyPaths(), payload, false, mk); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("write key files: %v", err)
	}
	if _, err := ir.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
}

// assertNoLineBreak checks the wire: JSON writes a line break in a string as \n.
func assertNoLineBreak(t *testing.T, listing string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`\n`)) {
		t.Fatalf("%s serves a line break: %s", listing, data)
	}
}
