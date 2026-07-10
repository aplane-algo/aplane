// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
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

// RoutingFamily returns the algorithm family name.
func (p *LogicSigProvider) RoutingFamily() string {
	return p.family
}

// LoadKeysFromData loads key material from decrypted key file JSON.
// SECURITY: the private key copy is handed to the returned KeyMaterial, whose
// owner is responsible for zeroing it.
func (p *LogicSigProvider) LoadKeysFromData(data []byte) (*KeyMaterial, error) {
	payload, err := keys.ParsePayload(data)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()

	signingKeyType := payload.BaseKeyType
	if signingKeyType == "" {
		signingKeyType = payload.KeyType
	}
	if logicsigdsa.RoutingFamily(signingKeyType) != p.family {
		return nil, fmt.Errorf("key type %q does not belong to family %q", signingKeyType, p.family)
	}

	return &KeyMaterial{
		Type:                   payload.KeyType,
		Category:               payload.Category,
		BaseKeyType:            payload.BaseKeyType,
		SigningArgs:            keys.SigningArgDefs(payload.SigningArgs),
		SigningMetadataVersion: payload.SigningMetadataVersion,
		Value: &LsigKeyMaterial{
			PrivateKey: append([]byte(nil), payload.PrivateKey...),
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

	payload, err := keys.ParsePayload(keyData)
	if err != nil {
		return false
	}
	defer payload.ZeroSecrets()

	signingKeyType := payload.BaseKeyType
	if signingKeyType == "" {
		signingKeyType = payload.KeyType
	}
	return logicsigdsa.RoutingFamily(signingKeyType) == p.family
}
