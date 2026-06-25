// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

// LogicSigSignerOps defines signer-only operations for a versioned LogicSig key type.
type LogicSigSignerOps interface {
	Sign(privateKey []byte, message []byte) (signature []byte, err error)
}

// LogicSigProvider implements Provider for any LogicSig-based DSA family.
// It delegates cryptographic operations to signer-side ops registered by key type.
type LogicSigProvider struct {
	family          string
	signerOpsByType map[string]LogicSigSignerOps
}

// NewLogicSigProvider returns a signing provider with explicit signer ops.
func NewLogicSigProvider(family string, signerOpsByType map[string]LogicSigSignerOps) *LogicSigProvider {
	if len(signerOpsByType) == 0 {
		panic("LogicSig signing provider requires signer ops")
	}
	opsCopy := make(map[string]LogicSigSignerOps, len(signerOpsByType))
	for keyType, ops := range signerOpsByType {
		if ops == nil {
			panic("LogicSig signing provider got nil signer ops for key type: " + keyType)
		}
		opsCopy[keyType] = ops
	}
	return &LogicSigProvider{
		family:          family,
		signerOpsByType: opsCopy,
	}
}

// LsigKeyMaterial holds the raw private key bytes for LogicSig signing.
type LsigKeyMaterial struct {
	PrivateKey []byte
}

// Family returns the algorithm family name.
func (p *LogicSigProvider) Family() string {
	return p.family
}

// LoadKeysFromData loads key material from decrypted key file JSON.
// SECURITY: the decoded private key is handed to the returned KeyMaterial,
// whose owner is responsible for zeroing it. The intermediate hex string is
// immutable and cannot be zeroed; only its reference is dropped.
func (p *LogicSigProvider) LoadKeysFromData(data []byte) (*KeyMaterial, error) {
	if bytecode := keys.ExtractBytecode(data); len(bytecode) > 0 {
		if _, err := keys.ValidateLogicSigSaltedBytecode(data, bytecode); err != nil {
			return nil, err
		}
	}

	var keyPair keys.KeyPair
	if err := json.Unmarshal(data, &keyPair); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keys: %w", err)
	}

	signingKeyType := keyPair.BaseKeyType
	if signingKeyType == "" {
		signingKeyType = keyPair.KeyType
	}
	if logicsigdsa.RoutingFamily(signingKeyType) != p.family {
		return nil, fmt.Errorf("key type %q does not belong to family %q", signingKeyType, p.family)
	}

	privBytes, err := hex.DecodeString(keyPair.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex: %w", err)
	}

	// Drop reference to the hex string so it becomes GC-eligible.
	defer func() {
		keyPair.PrivateKeyHex = ""
	}()

	return &KeyMaterial{
		Type:                   keyPair.KeyType,
		Category:               keyPair.Category,
		BaseKeyType:            keyPair.BaseKeyType,
		SigningArgs:            keys.SigningArgDefs(keyPair.SigningArgs),
		SigningMetadataVersion: keyPair.SigningMetadataVersion,
		Value: &LsigKeyMaterial{
			PrivateKey: privBytes,
		},
	}, nil
}

// SignMessage signs a message using the DSA registered for the key's type.
func (p *LogicSigProvider) SignMessage(key *KeyMaterial, message []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("key material is nil")
	}

	signingKeyType := key.BaseKeyType
	if signingKeyType == "" {
		signingKeyType = key.Type
	}
	if logicsigdsa.RoutingFamily(signingKeyType) != p.family {
		return nil, fmt.Errorf("key type %q does not belong to family %q", signingKeyType, p.family)
	}

	km, ok := key.Value.(*LsigKeyMaterial)
	if !ok {
		return nil, fmt.Errorf("invalid key value for %s provider: expected *LsigKeyMaterial", p.family)
	}

	signerOps := p.signerOpsByType[signingKeyType]
	if signerOps == nil && signingKeyType != key.Type {
		signerOps = p.signerOpsByType[key.Type]
	}
	if signerOps == nil {
		signerOps = p.signerOpsByType[p.family]
	}
	if signerOps == nil {
		return nil, fmt.Errorf("no LogicSig signer ops registered for %s", key.Type)
	}

	sig, err := signerOps.Sign(km.PrivateKey, message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	return sig, nil
}

// ZeroKey securely zeros the private key material.
func (p *LogicSigProvider) ZeroKey(key *KeyMaterial) {
	if key == nil {
		return
	}

	if km, ok := key.Value.(*LsigKeyMaterial); ok {
		crypto.ZeroBytes(km.PrivateKey)
		km.PrivateKey = nil
	}

	key.Type = ""
	key.Value = nil
}

// DetectKeyType checks if unencrypted key data belongs to this provider's family.
func (p *LogicSigProvider) DetectKeyType(keyData []byte, passphrase string) bool {
	if passphrase != "" {
		return false
	}

	keyType, err := keys.DetectKeyTypeFromData(keyData)
	if err != nil {
		return false
	}

	meta := keys.ExtractSigningMetadata(keyData)
	signingKeyType := meta.BaseKeyType
	if signingKeyType == "" {
		signingKeyType = keyType
	}
	return logicsigdsa.RoutingFamily(signingKeyType) == p.family
}
