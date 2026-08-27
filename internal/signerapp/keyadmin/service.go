// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Error aliases the unified signer service-error model so key-admin error
// kinds share the wire-code and HTTP-status mapping with the signing service.
type (
	ErrorKind = svcerr.Kind
	Error     = svcerr.Error
)

const (
	ErrorInvalidInput      = svcerr.KindBadRequest
	ErrorInvalidPassphrase = svcerr.KindInvalidPassphrase
	ErrorLocked            = svcerr.KindLocked
	ErrorNotFound          = svcerr.KindNotFound
	ErrorCacheRefresh      = svcerr.KindCacheRefresh
	ErrorInternal          = svcerr.KindInternal
)

type GenerateResult struct {
	Address           string
	PublicKeyHex      string
	KeyType           string
	IsWitnessKey      bool
	IsSpendingAccount *bool
	Mnemonic          string
	Parameters        map[string]string
}

type DeleteResult struct {
	DeletedPath string
}

type ListKeyInfo struct {
	Address                  string
	KeyType                  string
	TemplateProvenanceStatus string
	TemplateProvenanceNote   string
}

type KeyDetailsResult struct {
	Address                  string
	KeyType                  string
	PublicKeyHex             string
	Parameters               map[string]string
	DisplayTEAL              string
	TemplateProvenanceStatus string
	TemplateProvenanceNote   string
}

type AuditLogger interface {
	LogKeyGenerated(address, keyType string)
	LogKeyDeleted(address, deletedPath string)
	LogKeyImported(address, keyType string)
}

type Locker interface {
	Lock()
	Unlock()
}

type Service struct {
	AuditLog     AuditLogger
	MutationLock func() Locker
	Runtime      *productruntime.Runtime
}

type GenerateGenericLSigFunc func(context.Context, *productruntime.Runtime, string, map[string]string) (string, error)

type boundedInventoryProvider interface {
	BoundedAuthorizationMetadata() *boundedmeta.Metadata
}

func (s Service) GenerateKey(ctx context.Context, keyType string, params map[string]string, generateGenericLSig GenerateGenericLSigFunc) (*GenerateResult, *Error) {
	ir := s.Runtime
	keyType = keytypecatalog.Canonicalize(keyType)
	if ctx == nil {
		ctx = context.Background()
	}
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}
	if keyType == "" {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "key_type is required"}
	}
	if roleErr := keyclass.ValidateKeyTypeAllowedForNodeRole(ir.NodeRole(), keyType); roleErr != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: roleErr.Error()}
	}
	if keytypes.IsGuardedAccountKeyType(keyType) {
		resolved, err := sentryrefs.ResolveCreationParams(ir.KeyPaths(), keyType, params)
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
		params = resolved
	} else if provider := lsigprovider.Get(keyType); provider != nil {
		if boundedProvider, ok := provider.(boundedInventoryProvider); ok {
			if metadata := boundedProvider.BoundedAuthorizationMetadata(); metadata != nil && metadata.Sentry != nil {
				resolved, err := sentryrefs.ResolveCreationParamsForComponent(
					ir.KeyPaths(), keyType, metadata.Sentry.ComponentKeyType, params,
				)
				if err != nil {
					return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
				}
				params = resolved
			}
		}
	}

	if provider := lsigprovider.Get(keyType); provider != nil {
		// Canonicalize at the admin boundary so persisted params and API responses
		// are stable; lower layers also normalize defensively.
		normalized, err := lsigprovider.NormalizeCreationParams(params, provider.CreationParams())
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
		params = normalized
		if boundedProvider, ok := provider.(boundedInventoryProvider); ok {
			if metadata := boundedProvider.BoundedAuthorizationMetadata(); metadata != nil && metadata.Sentry != nil {
				if err := validateVisibleSentryAuthorityCollisions(ir, params[boundedmeta.SentryPublicKeyParameter]); err != nil {
					return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
				}
			}
		}
	}

	unlockMutation := s.lockMutation()
	defer unlockMutation()
	activeKeyPaths, activeErr := ir.ActiveKeyPaths()
	if activeErr != nil {
		return nil, mapGenerateError(activeErr)
	}

	activated, activationErr := activatedKeyTypes(activeKeyPaths)
	if activationErr != nil {
		return nil, activationErr
	}
	canGenerate, stateErr := keytypestate.CanGenerate(activeKeyPaths, keyType)
	if stateErr != nil {
		return nil, &Error{Kind: ErrorInternal, Message: "failed to read key type state"}
	}
	if !canGenerate {
		return nil, &Error{Kind: ErrorInvalidInput, Message: fmt.Sprintf("invalid key type: %s", keyType)}
	}
	if genericlsig.IsGenericLSigType(keyType) {
		if generateGenericLSig == nil {
			return nil, &Error{Kind: ErrorInternal, Message: "generic lsig generator not configured"}
		}
		address, err := generateGenericLSig(ctx, ir, keyType, params)
		if err != nil {
			return nil, mapGenerateError(err)
		}
		return &GenerateResult{
			Address:    address,
			KeyType:    keyType,
			Parameters: params,
		}, nil
	}

	mut := storemut.New(activeKeyPaths, nil, nil)
	var genResult *keymgmt.GenerateResult
	err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		var genErr error
		genResult, genErr = mut.GenerateKeyWithActivatedContext(ctx, keyType, mk, params, activated)
		return genErr
	})
	if err != nil {
		return nil, mapGenerateError(err)
	}

	if reloadErr := reloadKeys(ir); reloadErr != nil {
		return nil, reloadErr
	}

	if s.AuditLog != nil {
		s.AuditLog.LogKeyGenerated(genResult.Address, genResult.KeyType)
	}

	return &GenerateResult{
		Address:           genResult.Address,
		PublicKeyHex:      genResult.PublicKeyHex,
		KeyType:           genResult.KeyType,
		IsWitnessKey:      genResult.IsWitnessKey,
		IsSpendingAccount: genResult.IsSpendingAccount,
		Mnemonic:          genResult.Mnemonic,
		Parameters:        params,
	}, nil
}

func validateVisibleSentryAuthorityCollisions(ir *productruntime.Runtime, sentryPublicKeyHex string) error {
	if ir == nil || ir.KeyStore() == nil {
		return nil
	}
	normalized := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sentryPublicKeyHex), "0x")))
	if normalized == "" {
		return nil
	}
	for selector, publicKeyHex := range ir.KeyStore().GetPublicKeyHexMap() {
		if strings.ToLower(strings.TrimSpace(publicKeyHex)) == normalized {
			return fmt.Errorf("bounded sentry public key collides with signer-managed key %s", selector)
		}
	}
	for selector, summary := range ir.KeyStore().GetSigningSummary() {
		if summary.BoundedAuthorization == nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(summary.BoundedAuthorization.AdminPublicKeyHex)) == normalized {
			return fmt.Errorf("bounded sentry public key collides with contract-admin authority enrolled by %s", selector)
		}
	}
	return nil
}

func (s Service) DeleteKey(address string) (*DeleteResult, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}
	if address == "" {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "address is required"}
	}
	var err error
	address, err = normalizeDeleteKeyID(address)
	if err != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	}

	unlockMutation := s.lockMutation()
	defer unlockMutation()
	activeKeyPaths, activeErr := ir.ActiveKeyPaths()
	if activeErr != nil {
		return nil, mapGenerateError(activeErr)
	}

	keyFile, err := ir.FindKeyFile(address)
	if err != nil {
		return nil, &Error{Kind: ErrorNotFound, Message: "key not found: " + address}
	}
	delResult, err := storemut.New(activeKeyPaths, nil, nil).DeleteKey(address, keyFile)
	if err != nil {
		return nil, &Error{Kind: ErrorInternal, Message: "key deletion failed: " + err.Error()}
	}

	if reloadErr := reloadKeys(ir); reloadErr != nil {
		return nil, reloadErr
	}

	if s.AuditLog != nil {
		s.AuditLog.LogKeyDeleted(address, delResult.DeletedPath)
	}

	return &DeleteResult{DeletedPath: delResult.DeletedPath}, nil
}

func activatedKeyTypes(paths storepaths.Paths) ([]string, *Error) {
	records, err := keytypestate.List(paths)
	if err != nil {
		return nil, &Error{Kind: ErrorInternal, Message: "failed to read key type state"}
	}
	enabled := make([]string, 0, len(records))
	for _, rec := range records {
		if rec.State == keytypestate.StateEnabled {
			enabled = append(enabled, rec.KeyType)
		}
	}
	return enabled, nil
}

func (s Service) lockMutation() func() {
	if s.MutationLock == nil {
		return func() {}
	}
	lock := s.MutationLock()
	if lock == nil {
		return func() {}
	}
	lock.Lock()
	return lock.Unlock
}

func mapGenerateError(err error) *Error {
	if isLockedStateError(err) {
		return &Error{Kind: ErrorLocked, Message: "signer is locked"}
	}
	if errors.Is(err, keygen.ErrInvalidParams) {
		return &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	}
	if errors.Is(err, errBadRequest) {
		return &Error{Kind: ErrorInvalidInput, Message: strings.TrimPrefix(err.Error(), errBadRequest.Error()+": ")}
	}
	if errors.Is(err, errCacheRefresh) {
		return &Error{Kind: ErrorCacheRefresh, Message: errCacheRefresh.Error()}
	}
	return &Error{Kind: ErrorInternal, Message: "key generation failed"}
}

func reloadKeys(ir *productruntime.Runtime) *Error {
	if _, err := ir.Reload(); err != nil {
		if isLockedStateError(err) {
			return &Error{Kind: ErrorLocked, Message: "signer is locked"}
		}
		return &Error{Kind: ErrorCacheRefresh, Message: "failed to refresh signer key cache"}
	}
	return nil
}

func isLockedStateError(err error) bool {
	return errors.Is(err, keystore.ErrStoreLocked)
}

func normalizeDeleteKeyID(address string) (string, error) {
	if witness.IsID(address) {
		selector, err := witness.NormalizeID(address)
		if err != nil {
			return "", err
		}
		return selector, nil
	}
	if _, err := types.DecodeAddress(strings.ToUpper(address)); err != nil {
		return "", fmt.Errorf("invalid key identifier")
	}
	return address, nil
}
