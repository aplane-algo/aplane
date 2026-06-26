// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package corridor provides the always-sentry corridor LogicSig provider.
package corridor

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/merklewhitelist"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	"github.com/aplane-algo/aplane/lsig/sentryaccount"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	FamilyName  = "aplane.corridor"
	KeyTypeV1   = keytypes.CorridorV1
	BaseKeyType = "aplane.falcon1024.v1"

	ParamRecipients      = "recipients"
	ParamSentryPublicKey = keytypes.ParameterSentryPublicKey

	SignatureSize = 4 + family.MaxSignatureSize + family.MaxSignatureSize
)

// Provider implements a Falcon-1024 account that requires both a user
// component signature and a Falcon-1024 sentry signature. Transfers are limited
// by an embedded recipient Merkle root; rekeys are handled by the sentry policy
// before the sentry signature is produced.
type Provider struct {
	sentryaccount.Meta
	sentryaccount.AlgodHolder
}

func NewProviderV1() *Provider {
	return &Provider{
		Meta: sentryaccount.Meta{
			KeyTypeName:            KeyTypeV1,
			BaseKeyTypeName:        BaseKeyType,
			FamilyName:             FamilyName,
			DisplayNameText:        "Corridor",
			DescriptionText:        "Falcon-1024 sentry account with recipient corridor and rekey policy",
			Color:                  family.DisplayColor,
			SignatureSizeBytes:     SignatureSize,
			MnemonicSchemeName:     family.MnemonicScheme,
			MnemonicWordCountValue: family.MnemonicWordCount,
		},
	}
}

func (p *Provider) CreationParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{
		{
			Name:        ParamRecipients,
			Label:       "Recipients",
			Description: "Allowed payment and asset-transfer recipients",
			Type:        "address[]",
			Required:    true,
			MinItems:    1,
			MaxItems:    merklewhitelist.MaxItems,
			Placeholder: "Comma-separated Algorand addresses",
		},
		sentryaccount.SentryPublicKeyParam(
			"Hex-encoded Falcon-1024 sentry public key embedded in the corridor account",
			family.PublicKeySize,
		),
	}
}

func (p *Provider) ValidateCreationParams(params map[string]string) error {
	normalized, err := lsigprovider.NormalizeCreationParams(params, p.CreationParams())
	if err != nil {
		return err
	}
	if err := generictemplate.ValidateParameterValues(normalized, p.CreationParams()); err != nil {
		return err
	}
	if _, err := merklewhitelist.RootFromRecipientsParam(normalized[ParamRecipients]); err != nil {
		return fmt.Errorf("%s: %w", ParamRecipients, err)
	}
	_, err = sentryaccount.DecodeSentryPublicKey(normalized[ParamSentryPublicKey], family.PublicKeySize)
	return err
}

// BuildArgs assembles LogicSig args as:
//
//	arg 0: Falcon user component signature
//	arg 1: Falcon sentry component signature
//
// /sign/assemble appends the generated Merkle proof as arg 2 when the target
// transaction spends to a non-self recipient.
func (p *Provider) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	if err := sentryaccount.RejectRuntimeArgs(runtimeArgs); err != nil {
		return nil, err
	}
	userSig, sentrySig, err := UnpackComponentSignatures(signature)
	if err != nil {
		return nil, err
	}
	return [][]byte{userSig, sentrySig}, nil
}

func (p *Provider) DeriveLsig(ctx context.Context, publicKey []byte, params map[string]string) ([]byte, string, error) {
	result, err := p.DeriveLsigWithSalt(ctx, publicKey, params)
	if err != nil {
		return nil, "", err
	}
	return result.Bytecode, result.Address.String(), nil
}

func (p *Provider) DeriveLsigWithSalt(ctx context.Context, publicKey []byte, params map[string]string) (lsigsalt.FindResult, error) {
	teal, err := p.GenerateTEAL(publicKey, params)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	client, err := p.AlgodClient()
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	return sentryaccount.CompileSalted(ctx, client, teal)
}

func (p *Provider) GenerateTEAL(publicKey []byte, params map[string]string) (string, error) {
	if len(publicKey) != family.PublicKeySize {
		return "", fmt.Errorf("invalid Falcon public key size: expected %d, got %d", family.PublicKeySize, len(publicKey))
	}
	normalized, err := lsigprovider.NormalizeCreationParams(params, p.CreationParams())
	if err != nil {
		return "", err
	}
	if err := p.ValidateCreationParams(normalized); err != nil {
		return "", err
	}
	sentryPublicKey, err := sentryaccount.DecodeSentryPublicKey(normalized[ParamSentryPublicKey], family.PublicKeySize)
	if err != nil {
		return "", err
	}
	root, err := merklewhitelist.RootFromRecipientsParam(normalized[ParamRecipients])
	if err != nil {
		return "", fmt.Errorf("%s: %w", ParamRecipients, err)
	}

	return fmt.Sprintf(`#pragma version 12

// Counter marker (varied 0-255 to avoid ed25519 curve addresses)
byte 0x%s
pop

// === User Falcon-1024 component signature ===
pushbytes 0x%s
pushbytes 0x%02x
concat
txn TxID
concat
sha512_256
arg 0
pushbytes 0x%s
falcon_verify
assert

// === Sentry Falcon-1024 component signature ===
pushbytes 0x%s
pushbytes 0x%02x
concat
txn TxID
concat
sha512_256
arg 1
pushbytes 0x%s
falcon_verify
assert

txn RekeyTo
global ZeroAddress
==
bnz corridor_transfer_path

// Rekeys must be pure 0 ALGO self-payments. The sentry's off-chain rekey_policy
// decides whether a specific sender -> rekey target edge is allowed.
txn TypeEnum
int pay
==
assert
txn Amount
int 0
==
assert
txn Receiver
txn Sender
==
assert
txn CloseRemainderTo
global ZeroAddress
==
assert
b corridor_allow

corridor_transfer_path:
txn TypeEnum
int pay
==
bnz corridor_pay_path
txn TypeEnum
int axfer
==
bnz corridor_axfer_path
err

corridor_pay_path:
txn CloseRemainderTo
global ZeroAddress
==
txn CloseRemainderTo
txn Receiver
==
||
assert
txn Receiver
txn Sender
==
bnz corridor_allow
txn Receiver
callsub corridor_verify_member
assert
b corridor_allow

corridor_axfer_path:
txn AssetSender
global ZeroAddress
==
assert
txn AssetCloseTo
global ZeroAddress
==
txn AssetCloseTo
txn AssetReceiver
==
||
assert
txn AssetReceiver
txn Sender
==
bnz corridor_allow
txn AssetReceiver
callsub corridor_verify_member
assert
b corridor_allow

corridor_allow:
int 1
return

// Verify arg 2 is a fixed-depth Merkle proof for the address on top of stack.
corridor_verify_member:
store 0
arg 2
len
int 512
==
assert
byte 0x00
load 0
concat
sha256
store 1
int 0
store 2

corridor_merkle_loop:
load 2
int 16
<
bz corridor_merkle_done
arg 2
load 2
int 32
*
int 32
extract3
store 3
load 1
load 3
b<
bnz corridor_current_first
load 3
store 4
load 1
store 5
b corridor_hash_pair
corridor_current_first:
load 1
store 4
load 3
store 5
corridor_hash_pair:
byte 0x01
load 4
concat
load 5
concat
sha256
store 1
load 2
int 1
+
store 2
b corridor_merkle_loop

corridor_merkle_done:
load 1
pushbytes 0x%s
==
retsub
`, lsigsalt.PushbytesSaltMarkerHex(0),
		hex.EncodeToString([]byte(message.DomainTagV1)),
		byte(message.RoleUser),
		hex.EncodeToString(publicKey),
		hex.EncodeToString([]byte(message.DomainTagV1)),
		byte(message.RoleSentry),
		hex.EncodeToString(sentryPublicKey),
		hex.EncodeToString(root[:])), nil
}

// CompatibilityFingerprint returns the behavior-only compatibility fingerprint
// for this corridor provider. Identity/display strings (key_type, family,
// version) are excluded; the renameable base key type is projected to a stable
// base_primitive token. The Merkle proof layout, rekey policy, salt style, and
// component argument layout remain hashed. Provenance only — never read on the
// signing path.
func (p *Provider) CompatibilityFingerprint() string {
	type canonicalSpec struct {
		BasePrimitive string `json:"base_primitive"`
		SaltStyle     string `json:"salt_style"`
		MerkleDepth   int    `json:"merkle_depth"`
		MerkleArg     string `json:"merkle_arg"`
		RekeyPolicy   string `json:"rekey_policy"`
		Arg0          string `json:"arg0"`
		Arg1          string `json:"arg1"`
	}
	return lsigprovider.HashCompatibilitySpec(canonicalSpec{
		BasePrimitive: lsigprovider.FingerprintBasePrimitive(p.BaseKeyType()),
		SaltStyle:     string(lsigsalt.StylePushbytes),
		MerkleDepth:   merklewhitelist.Depth,
		MerkleArg:     "arg2",
		RekeyPolicy:   "sentry_policy.rekey_policy",
		Arg0:          "user_falcon1024_component_signature",
		Arg1:          "sentry_falcon1024_component_signature",
	})
}

var componentCodec = sentryaccount.ComponentCodec{
	UserLabel:   "user Falcon",
	UserMaxSize: family.MaxSignatureSize,
	SentryLabel: "sentry Falcon",
	SentrySize:  sentryaccount.VariableSentrySize(family.MaxSignatureSize),
	BlobLabel:   "corridor",
}

func PackComponentSignatures(userSignature, sentrySignature []byte) ([]byte, error) {
	return componentCodec.Pack(userSignature, sentrySignature)
}

func (p *Provider) PackComponentSignatures(userSignature, sentrySignature []byte) ([]byte, error) {
	return PackComponentSignatures(userSignature, sentrySignature)
}

func UnpackComponentSignatures(signature []byte) ([]byte, []byte, error) {
	return componentCodec.Unpack(signature)
}

func (p *Provider) AssemblyExtraArgs(txn types.Transaction, params map[string]string) ([][]byte, error) {
	proof, err := corridorProofArg(txn, params)
	if err != nil {
		return nil, fmt.Errorf("corridor proof generation failed: %w", err)
	}
	if len(proof) == 0 {
		return nil, nil
	}
	return [][]byte{proof}, nil
}

func corridorProofArg(txn types.Transaction, params map[string]string) ([]byte, error) {
	if params == nil || strings.TrimSpace(params[ParamRecipients]) == "" {
		return nil, fmt.Errorf("corridor key file missing recipients parameter")
	}
	if !txn.RekeyTo.IsZero() {
		return corridorRekeyProofArg(txn)
	}

	var receiver types.Address
	switch txn.Type {
	case types.PaymentTx:
		receiver = txn.Receiver
	case types.AssetTransferTx:
		receiver = txn.AssetReceiver
	default:
		return nil, fmt.Errorf("corridor only supports pay and axfer targets, got %s", txn.Type)
	}
	if receiver == txn.Sender {
		return nil, nil
	}
	return merklewhitelist.ProofForAddressParam(params[ParamRecipients], receiver)
}

func corridorRekeyProofArg(txn types.Transaction) ([]byte, error) {
	if txn.Type != types.PaymentTx {
		return nil, fmt.Errorf("corridor rekey targets must be payment transactions")
	}
	if txn.Amount != 0 {
		return nil, fmt.Errorf("corridor rekey targets must transfer 0 microalgos")
	}
	if txn.Receiver != txn.Sender {
		return nil, fmt.Errorf("corridor rekey targets must be self-payments")
	}
	if !txn.CloseRemainderTo.IsZero() {
		return nil, fmt.Errorf("corridor rekey targets must not close remainder")
	}
	return nil, nil
}

var (
	_ logicsigdsa.LogicSigDSA        = (*Provider)(nil)
	_ logicsigdsa.TEALGenerator      = (*Provider)(nil)
	_ logicsigdsa.SaltedDeriver      = (*Provider)(nil)
	_ lsigprovider.LSigProvider      = (*Provider)(nil)
	_ lsigprovider.SigningProvider   = (*Provider)(nil)
	_ lsigprovider.MnemonicProvider  = (*Provider)(nil)
	_ lsigprovider.AlgodConfigurable = (*Provider)(nil)
)
