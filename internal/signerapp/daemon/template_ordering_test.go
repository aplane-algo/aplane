// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestReloadKeysRegistersTemplatesBeforeKeyScan(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("phase0-ordering-%d", time.Now().UnixNano())
	keyType := "test." + family + ".v1"
	bytecode := []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01} // #pragma version 6; int 1

	if genericlsig.Get(keyType) != nil {
		t.Fatalf("test key type %q already registered; family generator must be unique", keyType)
	}

	address, err := logicSigAddressForTest(bytecode)
	if err != nil {
		t.Fatalf("logicSigAddressForTest() error = %v", err)
	}

	saveGenericTemplateForTest(t, server, keyType, []byte(fmt.Sprintf(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: %s
version: 1
display_name: "Ordering Template"
description: "ordering check"
max_opcode_cost: 20000
runtime_args:
  - name: preimage
    label: "Preimage"
    type: bytes
    required: true
    byte_length: 32
teal: |
  #pragma version 8
  int 1
`, family)))

	ir := server.productRuntime()
	err = ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		signingArgs := []keys.StoredSigningArg{{
			Name:       "preimage",
			Label:      "Preimage",
			Type:       "bytes",
			Required:   true,
			ByteLength: 32,
		}}
		payload := keys.NewGenericLSigPayload(keyType, nil, bytecode, 5, "#pragma version 6\nint 1", signingArgs, "")
		if profileErr := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); profileErr != nil {
			return profileErr
		}
		result, saveErr := keys.SavePayload(mustActiveKeyPaths(t, server), payload, masterKey)
		if saveErr == nil && result.Address != address {
			return fmt.Errorf("saved address %s does not match expected %s", result.Address, address)
		}
		return saveErr
	})
	if err != nil {
		t.Fatalf("SavePayload() error = %v", err)
	}

	// Standalone key metadata lets key inventory classify and expose signing args
	// before the matching template has been registered for generation.
	ks := ir.KeyStore()
	if err := ks.Scan(nil); err != nil {
		t.Fatalf("keyStore.Scan(nil) error = %v", err)
	}
	ir.PublishSnapshot(ks.GetCache(), ks.GetKeyTypes())

	preReloadInfo, ok := findKeyInfoResponse(server.restService().BuildKeyInfoList(ir), address)
	if !ok {
		t.Fatalf("address %q should still be visible after raw key scan", address)
	}
	if !preReloadInfo.IsGenericLsig {
		t.Fatalf("key %q should be classified as generic from stored key metadata", address)
	}
	if len(preReloadInfo.SigningArgs) != 1 || preReloadInfo.SigningArgs[0].Name != "preimage" {
		t.Fatalf("signing args before template registration = %#v, want one preimage arg", preReloadInfo.SigningArgs)
	}

	// Production order: register templates first, then scan keys.
	if err := reloadKeysWithTemplatesForTest(server); err != nil {
		t.Fatalf("reloadKeysWithTemplatesForTest() error = %v", err)
	}

	_, err = ir.FindKeyFile(address)
	if err != nil {
		t.Fatalf("address %q not visible after production reload path: %v", address, err)
	}

	postReloadInfo, ok := findKeyInfoResponse(server.restService().BuildKeyInfoList(ir), address)
	if !ok {
		t.Fatalf("address %q missing from key info list after production reload", address)
	}
	if !postReloadInfo.IsGenericLsig {
		t.Fatalf("key %q should be classified as generic after template registration", address)
	}
	if len(postReloadInfo.SigningArgs) != 1 || postReloadInfo.SigningArgs[0].Name != "preimage" {
		t.Fatalf("signing args after production reload = %#v, want one preimage arg", postReloadInfo.SigningArgs)
	}

	keyTypes := fetchKeyTypesForTest(t, server)
	info, ok := findKeyTypeInfo(keyTypes, keyType)
	if !ok {
		t.Fatalf("key type %q not visible via /keytypes after production reload", keyType)
	}
	if info.DisplayName != "Ordering Template" {
		t.Fatalf("DisplayName = %q, want %q", info.DisplayName, "Ordering Template")
	}
}

func logicSigAddressForTest(bytecode []byte) (string, error) {
	lsig := algocrypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	addr, err := lsig.Address()
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func findKeyInfoResponse(keyInfos []signerapi.KeyInfo, address string) (signerapi.KeyInfo, bool) {
	for _, info := range keyInfos {
		if info.Address == address {
			return info, true
		}
	}
	return signerapi.KeyInfo{}, false
}
