// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/merkleallowlist"
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon1024 "github.com/aplane-algo/aplane/lsig/falcon1024"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestCorridorGoldenVector(t *testing.T) {
	falcon1024.RegisterClient()
	data, err := templates.ReadFile("aplane.corridor.v1.yaml")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	spec, err := composeddsa.ParseTemplateSpec(data)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	if provider.KeyType() != "aplane.corridor.v1" || provider.BaseKeyType() != "aplane.falcon1024.v1" {
		t.Fatalf("provider identity = %q / %q", provider.KeyType(), provider.BaseKeyType())
	}

	lowRecipient := types.Address{}
	highRecipient := types.Address{}
	for i := range lowRecipient {
		lowRecipient[i] = 0x11
		highRecipient[i] = 0x22
	}
	recipients := strings.Join([]string{highRecipient.String(), lowRecipient.String()}, ",")
	spendingKey := bytes.Repeat([]byte{0x11}, falconfamily.PublicKeySize)
	sentryKey := bytes.Repeat([]byte{0x22}, falconfamily.PublicKeySize)
	adminKey := bytes.Repeat([]byte{0x33}, composeddsa.BoundedAdminPublicKeySize)
	params := map[string]string{
		"recipients": recipients,
		composeddsa.BoundedSentryPublicKeyParameter: hex.EncodeToString(sentryKey),
		composeddsa.BoundedAdminPublicKeyParameter:  hex.EncodeToString(adminKey),
	}

	metadata, err := provider.BuildBoundedAuthorizationMetadata(spendingKey, params, nil)
	if err != nil {
		t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
	}
	profileEncoding, err := composeddsa.CanonicalBoundedProfile(provider.BoundedAuthorizationProfile(), metadata)
	if err != nil {
		t.Fatalf("CanonicalBoundedProfile() error = %v", err)
	}
	const wantProfile = "" +
		"0000001941504c414e455f424f554e4445445f50524f46494c455f5631000000" +
		"08626f756e646564310000000300000003706179000000056178666572000000" +
		"0c61737365745f6f70745f696e0000000000002710000000010000000572656b" +
		"65790000000961646d696e5f6b6579000000046e6f6e65000000010000000773" +
		"656e747279310000001c61706c616e652e7769746e6573732d66616c636f6e31" +
		"3032342e76310000050000000001000000057370656e64000000106d65726b6c" +
		"655f616c6c6f776c6973740000000100000500000000010000000c6d65726b6c" +
		"655f70726f6f66000000166d65726b6c655f616c6c6f776c6973745f70726f6f" +
		"660000000a726563697069656e74730000020000000000000000040000000000" +
		"000010626173655f7369676e61747572655f300000000e626173655f7369676e" +
		"6174757265000005000000000872657175697265640000000872657175697265" +
		"64000000087265717569726564000000010000000c6d65726b6c655f70726f6f" +
		"66000000076465726976656400000200000000086f7074696f6e616c00000009" +
		"666f7262696464656e00000009666f7262696464656e00000002000000107365" +
		"6e7472795f7369676e61747572650000000673656e7472790000050000000008" +
		"726571756972656400000009666f7262696464656e00000009666f7262696464" +
		"656e000000030000000f61646d696e5f7369676e61747572650000000561646d" +
		"696e0000050000000009666f7262696464656e00000009666f7262696464656e" +
		"000000087265717569726564"
	if got := hex.EncodeToString(profileEncoding); got != wantProfile {
		t.Fatalf("canonical profile = %s, want %s", got, wantProfile)
	}
	if len(profileEncoding) != 588 {
		t.Fatalf("canonical profile length = %d, want 588", len(profileEncoding))
	}

	behaviorEncoding, err := composeddsa.CanonicalBoundedBehaviorParameters(params, provider.CreationParams())
	if err != nil {
		t.Fatalf("CanonicalBoundedBehaviorParameters() error = %v", err)
	}
	const wantBehaviorSHA256 = "8291e71b954d6b4815fd82f8a7dbb93e4a5124990e265b9c1a3a3c8060a7d64a"
	behaviorHash := sha256.Sum256(behaviorEncoding)
	if got := hex.EncodeToString(behaviorHash[:]); got != wantBehaviorSHA256 {
		t.Fatalf("canonical behavior SHA-256 = %s, want %s", got, wantBehaviorSHA256)
	}
	if len(behaviorEncoding) != 1979 {
		t.Fatalf("canonical behavior length = %d, want 1979", len(behaviorEncoding))
	}

	wantSlots := []boundedmeta.ArgumentSlot{
		{
			Index: 0, Name: "base_signature_0", Source: boundedmeta.ArgSourceBaseSignature, MaxSize: 1280,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgRequired, AdminRekey: boundedmeta.ArgRequired},
		},
		{
			Index: 1, Name: "merkle_proof", Source: boundedmeta.ArgSourceDerived, MaxSize: 512,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgOptional, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden},
		},
		{
			Index: 2, Name: boundedmeta.SentrySignatureSlot, Source: boundedmeta.ArgSourceSentry, MaxSize: 1280,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgRequired, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgForbidden},
		},
		{
			Index: 3, Name: "admin_signature", Source: boundedmeta.ArgSourceAdmin, MaxSize: 1280,
			Paths: boundedmeta.ArgumentPathMask{Spend: boundedmeta.ArgForbidden, SpendingRekey: boundedmeta.ArgForbidden, AdminRekey: boundedmeta.ArgRequired},
		},
	}
	if !reflect.DeepEqual(metadata.ArgumentLayout, wantSlots) {
		t.Fatalf("argument layout = %#v, want %#v", metadata.ArgumentLayout, wantSlots)
	}

	const (
		wantSentryKeyID = "MM3VSIAUKJ2BT2JBNB7V3HX2YUP7SMLWRWGWDQPEGSZ4ZRK6SLVQ"
		wantAdminKeyID  = "WCM6OW66SGGHSCTSAYDHOUGOPEXJLK2YPFQVUSWX6UASKCWRC4DQ"
		wantRoot        = "ea4421efa4bc1d9d5bfaf9d578e25655591bd27af8658bf94eee1687ec9c5d8d"
		wantBinding     = "4da9e512e48629601b5065850ef7514023251363d4664cfe9b941a108c6dd837"
		wantAdminMsg    = "f4ff0b4c08ca085cea41db660f91952225428f474f169ad2cf3ebfcdbf14073e"
	)
	if metadata.Sentry == nil || metadata.Sentry.ComponentKeyID != wantSentryKeyID {
		t.Fatalf("sentry key ID = %#v, want %s", metadata.Sentry, wantSentryKeyID)
	}
	if metadata.Sentry.PublicKeyHex != hex.EncodeToString(sentryKey) {
		t.Fatalf("resolved sentry public key does not match the vector input")
	}
	if metadata.AdminKeyID != wantAdminKeyID {
		t.Fatalf("admin key ID = %s, want %s", metadata.AdminKeyID, wantAdminKeyID)
	}
	if metadata.AdminPublicKeyHex != hex.EncodeToString(adminKey) {
		t.Fatalf("resolved admin public key does not match the vector input")
	}

	root, err := merkleallowlist.RootFromRecipientsParam(recipients)
	if err != nil {
		t.Fatalf("RootFromRecipientsParam() error = %v", err)
	}
	if got := hex.EncodeToString(root[:]); got != wantRoot {
		t.Fatalf("Merkle root = %s, want %s", got, wantRoot)
	}
	proof, err := merkleallowlist.ProofForAddressParam(recipients, highRecipient)
	if err != nil {
		t.Fatalf("ProofForAddressParam() error = %v", err)
	}
	const wantProof = "" +
		"4635e1fa62a599a7880a8d14a56f720a1d40f6e5448ab5a5e39bedc8bd87fa8e" +
		"fe43d66afa4a9a5c4f9c9da89f4ffb52635c8f342e7ffb731d68e36c5982072a" +
		"deb82e155954d6be14592c66ccf7a1ece193eeebcdabaf747b91f44519f09f47" +
		"2960044c62f2354e945e8d78fdd220a05f2c0879f24df6f11ef5cc26b5270a0e" +
		"4cfabc48c6898a30b1b5d12dda8e09a96e9ea17e80f4b2a050b8a8b4803fbd43" +
		"7162ed848f19740e53766ce01ac099523b099d593e0782ddbc5296eece50ec50" +
		"2be3cf0551cc6936d461e3dc43f3c4bf50cbee1bc091925254e879f4e7665e94" +
		"12db5262a5500d2516b8f82362d2a87278d20f712ff1fce2019d42ecba17241d" +
		"1a1a9265f869676c206824aa7bfc2fe8c7fe34691dddfb35797b6a321f977dfc" +
		"6e0bb8243e268be3d2fa3ce83234b2f850c85162bd0fced30e919e069bd52df7" +
		"0162892fa669b555682d4c5666f42c98f230e76406d646e6dbbcefb5d311e047" +
		"fd5593f0bfde08caa41745a8a6b2d5dcaea03a5867e8432a995bea3a1fd4df56" +
		"7bbcd27ae0b8f5d7c013dc6d13a2e586b58f83eac62aa62aa56f332288ad8bf4" +
		"d6c82f90e341cc36aa0fb5f8d03bbb3e6d5148eb56fcf79eb415574aee7fa99a" +
		"e2b649c4fa703c323fc2c929ad269dfdd150bde6862d9bcebe966244b983f20f" +
		"48c12a8dd675e9dcd3c63141fbfde6d11056c392b4379c3bbdc79a8511d0e65b"
	if got := hex.EncodeToString(proof); got != wantProof {
		t.Fatalf("Merkle proof = %s, want %s", got, wantProof)
	}

	binding := composeddsa.BoundedProgramBinding(
		provider.KeyType(),
		provider.BaseKeyType(),
		12,
		spendingKey,
		adminKey,
		profileEncoding,
		behaviorEncoding,
	)
	if got := hex.EncodeToString(binding[:]); got != wantBinding || got != metadata.ProgramBindingHex {
		t.Fatalf("program binding = %s / metadata %s, want %s", got, metadata.ProgramBindingHex, wantBinding)
	}
	adminMessage, err := composeddsa.BoundedAdminMessage(
		composeddsa.AdminOperationRekey,
		binding,
		bytes.Repeat([]byte{0x44}, 32),
	)
	if err != nil {
		t.Fatalf("BoundedAdminMessage() error = %v", err)
	}
	if got := hex.EncodeToString(adminMessage[:]); got != wantAdminMsg {
		t.Fatalf("admin message = %s, want %s", got, wantAdminMsg)
	}

	assertCorridorGoldenDocumentation(t, corridorGoldenDocumentation{
		ProfileHex:       wantProfile,
		BehaviorHex:      hex.EncodeToString(behaviorEncoding),
		BehaviorSHA256:   wantBehaviorSHA256,
		SentryKeyID:      wantSentryKeyID,
		AdminKeyID:       wantAdminKeyID,
		MerkleRoot:       wantRoot,
		MerkleProof:      wantProof,
		ProgramBinding:   wantBinding,
		AdminMessage:     wantAdminMsg,
		SelectedAddress:  highRecipient.String(),
		CanonicalAddress: lowRecipient.String(),
	})
}

type corridorGoldenDocumentation struct {
	ProfileHex       string
	BehaviorHex      string
	BehaviorSHA256   string
	SentryKeyID      string
	AdminKeyID       string
	MerkleRoot       string
	MerkleProof      string
	ProgramBinding   string
	AdminMessage     string
	SelectedAddress  string
	CanonicalAddress string
}

func assertCorridorGoldenDocumentation(t *testing.T, vector corridorGoldenDocumentation) {
	t.Helper()
	data, err := os.ReadFile("../../docs/ARCH_BOUNDED_DSA.md")
	if err != nil {
		t.Fatalf("read ARCH_BOUNDED_DSA.md: %v", err)
	}
	normalized := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "", "`", "").Replace(string(data))
	expected := map[string]string{
		"corridor_canonical_bounded_profile_length":     "588",
		"corridor_canonical_bounded_profile_hex":        vector.ProfileHex,
		"corridor_canonical_behavior_parameters_length": "1979",
		"corridor_canonical_behavior_parameters_hex":    vector.BehaviorHex,
		"corridor_canonical_behavior_parameters_sha256": vector.BehaviorSHA256,
		"corridor_sentry_key_id":                        vector.SentryKeyID,
		"corridor_contract_admin_key_id":                vector.AdminKeyID,
		"corridor_merkle_root":                          vector.MerkleRoot,
		"corridor_merkle_proof_hex":                     vector.MerkleProof,
		"corridor_bounded_program_binding":              vector.ProgramBinding,
		"corridor_admin_message":                        vector.AdminMessage,
		"corridor_selected_proof_recipient":             vector.SelectedAddress,
		"corridor_canonical_first_recipient":            vector.CanonicalAddress,
	}
	for label, value := range expected {
		if !strings.Contains(normalized, label+":"+value) {
			t.Errorf("ARCH_BOUNDED_DSA.md does not document %s %q", label, value)
		}
	}
	for _, row := range []string{
		"|0|base_signature_0|base_signature|1280|required|required|required|",
		"|1|merkle_proof|derived|512|optional|forbidden|forbidden|",
		"|2|sentry_signature|sentry|1280|required|forbidden|forbidden|",
		"|3|admin_signature|admin|1280|forbidden|forbidden|required|",
	} {
		if !strings.Contains(normalized, row) {
			t.Errorf("ARCH_BOUNDED_DSA.md does not document slot row %q", row)
		}
	}
}
