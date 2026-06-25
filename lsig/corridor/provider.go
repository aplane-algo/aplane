// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package corridor provides the always-sentry corridor LogicSig provider.
package corridor

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/merklewhitelist"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/generictemplate"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
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
	algodClient *algod.Client
	algodMu     sync.RWMutex
}

func NewProviderV1() *Provider {
	return &Provider{}
}

func (p *Provider) SetAlgodClient(client *algod.Client) {
	p.algodMu.Lock()
	defer p.algodMu.Unlock()
	p.algodClient = client
}

func (p *Provider) KeyType() string     { return KeyTypeV1 }
func (p *Provider) BaseKeyType() string { return BaseKeyType }
func (p *Provider) Family() string      { return FamilyName }
func (p *Provider) Version() int        { return 1 }
func (p *Provider) Category() string    { return lsigprovider.CategoryDSALsig }
func (p *Provider) DisplayName() string { return "Corridor" }
func (p *Provider) Description() string {
	return "Falcon-1024 sentry account with recipient corridor and rekey policy"
}
func (p *Provider) DisplayColor() string                      { return family.DisplayColor }
func (p *Provider) CryptoSignatureSize() int                  { return SignatureSize }
func (p *Provider) MnemonicScheme() string                    { return family.MnemonicScheme }
func (p *Provider) MnemonicWordCount() int                    { return family.MnemonicWordCount }
func (p *Provider) SupportsMnemonicImport() bool              { return false }
func (p *Provider) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }

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
		{
			Name:        ParamSentryPublicKey,
			Label:       "Sentry public key",
			Description: "Hex-encoded Falcon-1024 sentry public key embedded in the corridor account",
			Type:        "bytes",
			Required:    true,
			MaxLength:   family.PublicKeySize * 2,
			Example:     strings.Repeat("00", family.PublicKeySize),
		},
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
	_, err = decodeSentryPublicKey(normalized[ParamSentryPublicKey])
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
	if err := rejectRuntimeArgs(runtimeArgs); err != nil {
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
	if ctx == nil {
		ctx = context.Background()
	}
	p.algodMu.RLock()
	client := p.algodClient
	p.algodMu.RUnlock()
	if client == nil {
		return lsigsalt.FindResult{}, fmt.Errorf("algod client not set: configure algod.<network>.server in config.yaml")
	}

	teal, err := p.GenerateTEAL(publicKey, params)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	result, err := client.TealCompile([]byte(teal)).Do(ctx)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("TEAL compilation failed: %w", err)
	}
	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to decode compiled bytecode: %w", err)
	}
	salted, err := lsigsalt.FindOffCurve(bytecode, lsigsalt.PushbytesMarkerLocator)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to derive off-curve LogicSig address: %w", err)
	}
	return salted, nil
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
	sentryPublicKey, err := decodeSentryPublicKey(normalized[ParamSentryPublicKey])
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

func (p *Provider) CompatibilityFingerprint() string {
	type canonicalSpec struct {
		KeyType     string `json:"key_type"`
		BaseKeyType string `json:"base_key_type"`
		Family      string `json:"family"`
		Version     int    `json:"version"`
		SaltStyle   string `json:"salt_style"`
		MerkleDepth int    `json:"merkle_depth"`
		MerkleArg   string `json:"merkle_arg"`
		RekeyPolicy string `json:"rekey_policy"`
		Arg0        string `json:"arg0"`
		Arg1        string `json:"arg1"`
	}
	return lsigprovider.HashCompatibilitySpec(canonicalSpec{
		KeyType:     p.KeyType(),
		BaseKeyType: p.BaseKeyType(),
		Family:      p.Family(),
		Version:     p.Version(),
		SaltStyle:   string(lsigsalt.StylePushbytes),
		MerkleDepth: merklewhitelist.Depth,
		MerkleArg:   "arg2",
		RekeyPolicy: "sentry_policy.rekey_policy",
		Arg0:        "user_falcon1024_component_signature",
		Arg1:        "sentry_falcon1024_component_signature",
	})
}

func PackComponentSignatures(userSignature, sentrySignature []byte) ([]byte, error) {
	if len(userSignature) == 0 || len(userSignature) > family.MaxSignatureSize {
		return nil, fmt.Errorf("user Falcon signature length %d invalid (expected 1..%d bytes)", len(userSignature), family.MaxSignatureSize)
	}
	if len(sentrySignature) == 0 || len(sentrySignature) > family.MaxSignatureSize {
		return nil, fmt.Errorf("sentry Falcon signature length %d invalid (expected 1..%d bytes)", len(sentrySignature), family.MaxSignatureSize)
	}
	out := make([]byte, 4+len(userSignature)+len(sentrySignature))
	binary.BigEndian.PutUint16(out[:2], uint16(len(userSignature)))
	copy(out[2:], userSignature)
	offset := 2 + len(userSignature)
	binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(sentrySignature)))
	copy(out[offset+2:], sentrySignature)
	return out, nil
}

func UnpackComponentSignatures(signature []byte) ([]byte, []byte, error) {
	if len(signature) < 4 {
		return nil, nil, fmt.Errorf("corridor signature blob is too short")
	}
	userLen := int(binary.BigEndian.Uint16(signature[:2]))
	if userLen <= 0 || userLen > family.MaxSignatureSize {
		return nil, nil, fmt.Errorf("user Falcon signature length %d invalid (expected 1..%d bytes)", userLen, family.MaxSignatureSize)
	}
	if len(signature) < 2+userLen+2 {
		return nil, nil, fmt.Errorf("corridor signature blob is too short")
	}
	sentryOffset := 2 + userLen
	sentryLen := int(binary.BigEndian.Uint16(signature[sentryOffset : sentryOffset+2]))
	if sentryLen <= 0 || sentryLen > family.MaxSignatureSize {
		return nil, nil, fmt.Errorf("sentry Falcon signature length %d invalid (expected 1..%d bytes)", sentryLen, family.MaxSignatureSize)
	}
	if len(signature) != sentryOffset+2+sentryLen {
		return nil, nil, fmt.Errorf("invalid corridor signature blob length")
	}
	return signature[2:sentryOffset], signature[sentryOffset+2:], nil
}

func decodeSentryPublicKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("sentry_public_key must be hex: %w", err)
	}
	if len(decoded) != family.PublicKeySize {
		return nil, fmt.Errorf("sentry_public_key length %d invalid (expected %d bytes)", len(decoded), family.PublicKeySize)
	}
	return decoded, nil
}

func rejectRuntimeArgs(runtimeArgs map[string][]byte) error {
	if len(runtimeArgs) == 0 {
		return nil
	}
	for name := range runtimeArgs {
		return fmt.Errorf("unknown arg: %s", name)
	}
	return nil
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
