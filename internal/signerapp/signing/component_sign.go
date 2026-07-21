// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/signerapi"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
)

type componentKeyGetter interface {
	GetKeyWithContext(context.Context, string) (*coresigning.KeyMaterial, error)
}

// signPreparedSentryComponents is the narrow private-key operation for
// sentry-role component signatures. Callers must run deterministic
// sentry policy before invoking it.
func signPreparedSentryComponents(ctx context.Context, plan *ComponentSignPlan, session componentKeyGetter) (*ComponentSignResult, *ServiceError) {
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
		return nil, badRequest("sentry component signing requires sentry role")
	}
	if plan.ComponentKey == "" {
		return nil, badRequest("component_key is required for sentry component signing")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}

	keyMaterial, componentKey, err := loadSentryComponentKey(ctx, session, plan.ComponentKey)
	if err != nil {
		return nil, err
	}
	defer zeroLoadedKeyMaterial(keyMaterial)

	signatures := make([]signerapi.ComponentSignature, len(plan.Targets))
	for i, target := range plan.Targets {
		signature, signErr := signSentryComponentMessage(keyMaterial.Type, componentKey.PrivateKey, target.Message[:])
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
		ComponentKey: componentKey.WitnessKeyID,
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
			return nil, lockedError()
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

func loadSentryComponentKey(ctx context.Context, session componentKeyGetter, componentKeySelector string) (*coresigning.KeyMaterial, *coresigning.WitnessKeyMaterial, *ServiceError) {
	componentKeySelector, normalizeErr := witness.NormalizeID(componentKeySelector)
	if normalizeErr != nil {
		return nil, nil, badRequest(normalizeErr.Error())
	}

	keyMaterial, err := session.GetKeyWithContext(ctx, componentKeySelector)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrStoreLocked):
			return nil, nil, lockedError()
		case errors.Is(err, keystore.ErrKeyNotFound):
			return nil, nil, badRequest(fmt.Sprintf("Witness Key ID %q not found", componentKeySelector))
		default:
			return nil, nil, internal(fmt.Sprintf("failed to load sentry key: %v", err))
		}
	}
	if keyMaterial == nil {
		return nil, nil, internal("loaded sentry key material is nil")
	}
	if !witness.IsKeyType(keyMaterial.Type) {
		gotType := keyMaterial.Type
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, badRequest(fmt.Sprintf("key %q is %s, not a sentry key", componentKeySelector, gotType))
	}
	if keyMaterial.Category != "" && keyMaterial.Category != keys.CategoryWitness {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, badRequest(fmt.Sprintf("key %q is not a sentry key", componentKeySelector))
	}
	componentKey, ok := keyMaterial.Value.(*coresigning.WitnessKeyMaterial)
	if !ok || componentKey == nil {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded sentry key has invalid material")
	}
	if componentKey.WitnessKeyID != componentKeySelector {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal("loaded Witness Key ID does not match requested Witness Key ID")
	}
	publicKeySize, _ := witness.PublicKeySize(keyMaterial.Type)
	privateKeySize, _ := witness.PrivateKeySize(keyMaterial.Type)
	if len(componentKey.PrivateKey) != privateKeySize {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded sentry key has private key length %d", len(componentKey.PrivateKey)))
	}
	if len(componentKey.PublicKey) != publicKeySize {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(fmt.Sprintf("loaded sentry key has public key length %d", len(componentKey.PublicKey)))
	}
	if err := validateLoadedSentryComponentPair(keyMaterial.Type, componentKey.PublicKey, componentKey.PrivateKey); err != nil {
		zeroLoadedKeyMaterial(keyMaterial)
		return nil, nil, internal(err.Error())
	}
	return keyMaterial, componentKey, nil
}

func signSentryComponentMessage(keyType string, privateKey, msg []byte) ([]byte, *ServiceError) {
	if err := witness.RequireCapability(witness.CustodianNetworkedSigner, witness.DomainSentryComponent); err != nil {
		return nil, internal(err.Error())
	}
	switch keyType {
	case witness.Falcon1024V1:
		signature, err := signerops.New(nil).Sign(privateKey, msg)
		if err != nil {
			return nil, internal(fmt.Sprintf("failed to sign Falcon sentry component message: %v", err))
		}
		return signature, nil
	default:
		return nil, badRequest(fmt.Sprintf("key type %q is not a sentry key", keyType))
	}
}

func validateLoadedSentryComponentPair(keyType string, publicKey, privateKey []byte) error {
	if err := witness.ValidatePair(keyType, publicKey, privateKey); err != nil {
		return fmt.Errorf("loaded sentry key validation failed: %w", err)
	}
	return nil
}
