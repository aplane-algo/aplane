// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"

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
	IsComponentKey    bool
	IsSpendingAccount *bool
	Mnemonic          string
	Parameters        map[string]string
}

type DeleteResult struct {
	DeletedPath string
}

type SyncSentryReferencesResult struct {
	Added   int
	Updated int
	Removed int
	Records []sentryrefs.Record
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
	LogKeyGenerated(identityID, address, keyType string)
	LogKeyDeleted(identityID, address, deletedPath string)
	LogKeyImported(identityID, address, keyType string)
}

type Locker interface {
	Lock()
	Unlock()
}

type Service struct {
	AuditLog     AuditLogger
	MutationLock func(identityID string) Locker
}

type GenerateGenericLSigFunc func(context.Context, *identity.Runtime, string, map[string]string) (string, error)

func (s Service) GenerateKey(ctx context.Context, ir *identity.Runtime, keyType string, params map[string]string, generateGenericLSig GenerateGenericLSigFunc) (*GenerateResult, *Error) {
	keyType = keytypefmt.Canonicalize(keyType)
	if ctx == nil {
		ctx = context.Background()
	}
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "identity runtime is nil"}
	}
	if keyType == "" {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "key_type is required"}
	}
	if roleErr := keyclass.ValidateKeyTypeAllowedForNodeRole(ir.NodeRole(), keyType); roleErr != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: roleErr.Error()}
	}
	if keytypes.IsGuardedAccountKeyType(keyType) {
		resolved, err := sentryrefs.ResolveCreationParams(ir.KeyPaths(), ir.ID(), keyType, params)
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
		params = resolved
	}

	if provider := lsigprovider.Get(keyType); provider != nil {
		// Canonicalize at the admin boundary so persisted params and API responses
		// are stable; lower layers also normalize defensively.
		normalized, err := lsigprovider.NormalizeCreationParams(params, provider.CreationParams())
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
		params = normalized
	}

	unlockMutation := s.lockMutation(ir.ID())
	defer unlockMutation()

	activated, activationErr := activatedKeyTypes(ir)
	if activationErr != nil {
		return nil, activationErr
	}
	canGenerate, stateErr := keytypestate.CanGenerate(ir.KeyPaths(), ir.ID(), keyType)
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

	mut := storemut.New(ir.ID(), ir.KeyPaths(), nil, nil)
	var genResult *keymgmt.GenerateResult
	err := ir.WithMasterKey(func(mk []byte) error {
		var genErr error
		genResult, genErr = mut.GenerateKeyWithActivatedContext(ctx, keyType, mk, params, activated)
		return genErr
	})
	if err != nil {
		return nil, mapGenerateError(err)
	}

	if reloadErr := reloadIdentityKeys(ir); reloadErr != nil {
		return nil, reloadErr
	}

	if s.AuditLog != nil {
		s.AuditLog.LogKeyGenerated(ir.ID(), genResult.Address, genResult.KeyType)
	}

	return &GenerateResult{
		Address:           genResult.Address,
		PublicKeyHex:      genResult.PublicKeyHex,
		KeyType:           genResult.KeyType,
		IsComponentKey:    genResult.IsComponentKey,
		IsSpendingAccount: genResult.IsSpendingAccount,
		Mnemonic:          genResult.Mnemonic,
		Parameters:        params,
	}, nil
}

func (s Service) DeleteKey(ir *identity.Runtime, address string) (*DeleteResult, *Error) {
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "identity runtime is nil"}
	}
	if address == "" {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "address is required"}
	}
	var err error
	address, err = normalizeDeleteKeyID(address)
	if err != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	}

	unlockMutation := s.lockMutation(ir.ID())
	defer unlockMutation()

	keyFile, err := ir.FindKeyFile(address)
	if err != nil {
		return nil, &Error{Kind: ErrorNotFound, Message: "key not found: " + address}
	}

	delResult, err := storemut.New(ir.ID(), ir.KeyPaths(), nil, nil).DeleteKey(address, keyFile)
	if err != nil {
		return nil, &Error{Kind: ErrorInternal, Message: "key deletion failed"}
	}

	if reloadErr := reloadIdentityKeys(ir); reloadErr != nil {
		return nil, reloadErr
	}

	if s.AuditLog != nil {
		s.AuditLog.LogKeyDeleted(ir.ID(), address, delResult.DeletedPath)
	}

	return &DeleteResult{DeletedPath: delResult.DeletedPath}, nil
}

func (s Service) SyncSentryReferences(ir *identity.Runtime, discovered []sentryrefs.DiscoveredRecord) (*SyncSentryReferencesResult, *Error) {
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "identity runtime is nil"}
	}

	unlockMutation := s.lockMutation(ir.ID())
	defer unlockMutation()

	result, err := sentryrefs.SyncDiscovered(ir.KeyPaths(), ir.ID(), discovered)
	if err != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	}
	return &SyncSentryReferencesResult{
		Added:   result.Added,
		Updated: result.Updated,
		Removed: result.Removed,
		Records: result.Records,
	}, nil
}

func activatedKeyTypes(ir *identity.Runtime) ([]string, *Error) {
	records, err := keytypestate.List(ir.KeyPaths(), ir.ID())
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

func (s Service) lockMutation(identityID string) func() {
	if s.MutationLock == nil {
		return func() {}
	}
	lock := s.MutationLock(identityID)
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

func reloadIdentityKeys(ir *identity.Runtime) *Error {
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
	if keytypes.IsComponentKeySelector(address) {
		selector, err := keytypes.NormalizeComponentKeySelector(address)
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
