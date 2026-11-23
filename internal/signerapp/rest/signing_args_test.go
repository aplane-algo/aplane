// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signingargs"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// /keys lists an aplane key's signing arguments only when its key file records
// some: a LogicSig key without any, and a key that is not a LogicSig, list
// none, and the signing summary carries none for them either.
func TestKeysListSigningArgsOnlyForKeysThatRecordThem(t *testing.T) {
	ir := setupProductRuntime(t, true)
	spec, err := generictemplate.ParseTemplateSpec([]byte(blockDescriptionGenericYAML))
	if err != nil {
		t.Fatal(err)
	}
	generic := generictemplate.NewYAMLTemplate(spec)
	lsigprovider.RegisterIfAbsent(generic)
	t.Cleanup(func() { lsigprovider.Unregister(generic.KeyType()) })
	writeTemplateStateForRestTest(t, ir.KeyPaths(), generic.KeyType(), templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)

	genericKey := func(bytecode []byte, args []keys.StoredSigningArg) *keys.Payload {
		payload := keys.NewGenericLSigPayload(generic.KeyType(), map[string]string{"limit": "1"}, bytecode, "", args, "")
		if err := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	withArgs := genericKey([]byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}, signingargs.FromRuntimeDefs(generic.RuntimeArgs()))
	withoutArgs := genericKey([]byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x03}, nil)
	public, private, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	native := keys.NewEd25519Payload(public, private)
	saveAndReload(t, ir, withArgs, withoutArgs, native)

	listed, svcErr := Service{}.Keys(ir)
	if svcErr != nil {
		t.Fatalf("Keys() error = %v", svcErr)
	}
	if len(listed.Keys) != 3 {
		t.Fatalf("Keys() returned %d keys, want 3", len(listed.Keys))
	}
	summaries := ir.KeyStore().GetSigningSummary()
	var listedWithArgs int
	for _, key := range listed.Keys {
		data, err := json.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		_, served := fields["signing_args"]
		summaryArgs := summaries[key.Address].SigningArgs
		if len(key.SigningArgs) == 1 && key.SigningArgs[0].Name == "secret" && served && len(summaryArgs) == 1 {
			listedWithArgs++
			continue
		}
		if len(key.SigningArgs) != 0 || served || summaryArgs != nil {
			t.Fatalf("%s %s lists signing args %+v (served %v, summary %+v), want none", key.KeyType, key.Address, key.SigningArgs, served, summaryArgs)
		}
	}
	if listedWithArgs != 1 {
		t.Fatalf("%d keys list the recorded signing args, want 1", listedWithArgs)
	}
}
