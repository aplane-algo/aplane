// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/attestor/message"
	"github.com/aplane-algo/aplane/internal/attestor/verify"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

type componentKeyGetter interface {
	GetKeyWithContext(context.Context, string) (*coresigning.KeyMaterial, error)
}

// signPreparedAttestorComponents is the narrow private-key operation for
// attestor-role component signatures. Callers must run deterministic
// attestor policy before invoking it.
func signPreparedAttestorComponents(ctx context.Context, plan *ComponentSignPlan, session componentKeyGetter) (*ComponentSignResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	if plan == nil {
		return nil, internal("component sign plan is nil")
	}
	if plan.MessageRole != message.RoleSentry {
		return nil, badRequest("attestor component signing requires attestor role")
	}
	if plan.ComponentKey == "" {
		return nil, badRequest("component_key is required for attestor component signing")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}

	keyMaterial, componentKey, err := loadAttestorComponentKey(ctx, session, plan.ComponentKey)
	if err != nil {
		return nil, err
	}
	defer zeroLoadedKeyMaterial(keyMaterial)

	signatures := make([]signerapi.ComponentSignature, len(plan.Targets))
	for i, target := range plan.Targets {
		signature, signErr := signAttestorComponentMessage(keyMaterial.Type, componentKey.PrivateKey, target.Message[:])
		if signErr != nil {
			return nil, signErr
		}
		signatures[i] = signerapi.ComponentSignature{
			TargetIndex:     target.TargetIndex,
			Signature:       hex.EncodeToString(signature),
			SignatureScheme: keyMaterial.Type,
		}
		crypto.ZeroBytes(signature)
	}

	return &ComponentSignResult{
		RequestID:    plan.RequestID,
		ComponentKey: componentKey.ComponentKey,
		Signatures:   signatures,
	}, nil
}

func signPreparedUserComponents(ctx context.Context, plan *ComponentSignPlan, session componentKeyGetter) (*ComponentSignResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	if plan == nil {
		return nil, internal("component sign plan is nil")
	}
	if plan.MessageRole != message.RoleUser {
		return nil, badRequest("user component signing requires user role")
	}
	if plan.ComponentKey == "" {
		return nil, badRequest("component_key is required for user component signing")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}
	for _, target := range plan.Targets {
		if target.Sender != plan.ComponentKey {
			return nil, badRequest(fmt.Sprintf(
				"target index %d sender %q does not match guarded account %q",
				target.TargetIndex,
				target.Sender,
				plan.ComponentKey,
			))
		}
	}

	keyMaterial, provider, signatureScheme, err := loadGuardedAccountSigningKey(ctx, session, plan.ComponentKey)
	if err != nil {
		return nil, err
	}
	defer zeroLoadedKeyMaterial(keyMaterial)

	signatures := make([]signerapi.ComponentSignature, len(plan.Targets))
	for i, target := range plan.Targets {
		signature, signErr := provider.SignMessage(keyMaterial, target.Message[:])
		if signErr != nil {
			return nil, internal(fmt.Sprintf("failed to sign user component message: %v", signErr))
		}
		signatures[i] = signerapi.ComponentSignature{
			TargetIndex:     target.TargetIndex,
			Signature:       hex.EncodeToString(signature),
			SignatureScheme: signatureScheme,
		}
		crypto.ZeroBytes(signature)
	}

	return &ComponentSignResult{
		RequestID:    plan.RequestID,
		ComponentKey: plan.ComponentKey,
		Signatures:   signatures,
	}, nil
}

func loadGuardedAccountSigningKey(ctx context.Context, session componentKeyGetter, guardedAccount string) (*coresigning.KeyMaterial, coresigning.Provider, string, *ServiceError) {
	keyMaterial, err := loadGuardedAccountKeyMaterial(ctx, session, guardedAccount)
	if err != nil {
		return nil, nil, "", err
	}
	if keyMaterial.BaseKeyType == "" {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, "", internal("loaded guarded account key is missing base key type")
	}

	provider := coresigning.GetProvider(keyMaterial.BaseKeyType)
	if provider == nil {
		baseKeyType := keyMaterial.BaseKeyType
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, "", internal(fmt.Sprintf("unsupported guarded account base key type: %s", baseKeyType))
	}
	return keyMaterial, provider, keyMaterial.BaseKeyType, nil
}

func loadGuardedAccountKeyMaterial(ctx context.Context, session componentKeyGetter, guardedAccount string) (*coresigning.KeyMaterial, *ServiceError) {
	keyMaterial, err := session.GetKeyWithContext(ctx, guardedAccount)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrStoreLocked):
			return nil, forbidden("signer is locked")
		case errors.Is(err, keystore.ErrKeyNotFound):
			return nil, badRequest(fmt.Sprintf("guarded account key %q not found", guardedAccount))
		default:
			return nil, internal(fmt.Sprintf("failed to load guarded account key: %v", err))
		}
	}
	if keyMaterial == nil {
		return nil, internal("loaded guarded account key material is nil")
	}
	if !keytypes.IsGuardedAccountKeyType(keyMaterial.Type) {
		gotType := keyMaterial.Type
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, badRequest(fmt.Sprintf("key %q is %s, not a guarded account key", guardedAccount, gotType))
	}
	if keyMaterial.Category != "" && keyMaterial.Category != keys.CategoryDSALsig {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, badRequest(fmt.Sprintf("key %q is not a dsa_lsig key", guardedAccount))
	}
	return keyMaterial, nil
}

func loadAttestorComponentKey(ctx context.Context, session componentKeyGetter, componentKeySelector string) (*coresigning.KeyMaterial, *coresigning.ComponentKeyMaterial, *ServiceError) {
	componentKeySelector, normalizeErr := keytypes.NormalizeComponentKeySelector(componentKeySelector)
	if normalizeErr != nil {
		return nil, nil, badRequest(normalizeErr.Error())
	}

	keyMaterial, err := session.GetKeyWithContext(ctx, componentKeySelector)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrStoreLocked):
			return nil, nil, forbidden("signer is locked")
		case errors.Is(err, keystore.ErrKeyNotFound):
			return nil, nil, badRequest(fmt.Sprintf("component key %q not found", componentKeySelector))
		default:
			return nil, nil, internal(fmt.Sprintf("failed to load component key: %v", err))
		}
	}
	if keyMaterial == nil {
		return nil, nil, internal("loaded component key material is nil")
	}
	if !keytypes.IsAttestorComponentKeyType(keyMaterial.Type) {
		gotType := keyMaterial.Type
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, badRequest(fmt.Sprintf("key %q is %s, not an attestor component key", componentKeySelector, gotType))
	}
	if keyMaterial.Category != "" && keyMaterial.Category != keys.CategoryComponent {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, badRequest(fmt.Sprintf("key %q is not a component key", componentKeySelector))
	}
	componentKey, ok := keyMaterial.Value.(*coresigning.ComponentKeyMaterial)
	if !ok || componentKey == nil {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded attestor component key has invalid material")
	}
	if componentKey.ComponentKey != componentKeySelector {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded component key selector does not match requested component key")
	}
	publicKeySize, _ := keytypes.ComponentPublicKeySize(keyMaterial.Type)
	privateKeySize, _ := keytypes.ComponentPrivateKeySize(keyMaterial.Type)
	if len(componentKey.PrivateKey) != privateKeySize {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded attestor component key has private key length %d", len(componentKey.PrivateKey)))
	}
	if len(componentKey.PublicKey) != publicKeySize {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded attestor component key has public key length %d", len(componentKey.PublicKey)))
	}
	if err := validateLoadedAttestorComponentPair(keyMaterial.Type, componentKey.PublicKey, componentKey.PrivateKey); err != nil {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(err.Error())
	}
	return keyMaterial, componentKey, nil
}

func signAttestorComponentMessage(keyType string, privateKey, msg []byte) ([]byte, *ServiceError) {
	switch keyType {
	case keytypes.AttestorComponentEd25519V1:
		if len(privateKey) != ed25519.PrivateKeySize {
			return nil, internal(fmt.Sprintf("loaded attestor component key has private key length %d", len(privateKey)))
		}
		return ed25519.Sign(ed25519.PrivateKey(privateKey), msg), nil
	case keytypes.AttestorComponentFalcon1024V1:
		signature, err := signerops.New(nil).Sign(privateKey, msg)
		if err != nil {
			return nil, internal(fmt.Sprintf("failed to sign Falcon attestor component message: %v", err))
		}
		return signature, nil
	default:
		return nil, badRequest(fmt.Sprintf("key type %q is not an attestor component key", keyType))
	}
}

func validateLoadedAttestorComponentPair(keyType string, publicKey, privateKey []byte) error {
	switch keyType {
	case keytypes.AttestorComponentEd25519V1:
		derivedPublicKey, ok := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
		if !ok || !bytes.Equal(derivedPublicKey, publicKey) {
			return fmt.Errorf("loaded attestor component key public key does not match private key")
		}
		return nil
	case keytypes.AttestorComponentFalcon1024V1:
		const probe = "APLANE_COMPONENT_KEY_LOAD_V1"
		signature, err := signerops.New(nil).Sign(privateKey, []byte(probe))
		if err != nil {
			return fmt.Errorf("loaded Falcon attestor component key validation failed: %w", err)
		}
		defer crypto.ZeroBytes(signature)
		if err := verify.VerifyFalcon1024(publicKey, []byte(probe), signature); err != nil {
			return fmt.Errorf("loaded attestor component key public key does not match private key")
		}
		return nil
	default:
		return fmt.Errorf("loaded key type %q is not an attestor component key", keyType)
	}
}
