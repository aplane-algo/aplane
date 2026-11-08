// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
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
	PolicyLabel              string
	MnemonicExportable       bool
}

type AuditLogger interface {
	LogKeyExported(ctx context.Context, address, keyType, outcome string)
	LogKeyGenerated(ctx context.Context, address, keyType string)
	LogKeyDeleted(ctx context.Context, address, deletedPath string)
	LogKeyImported(ctx context.Context, address, keyType string)
}

type Locker interface {
	Lock()
	Unlock()
}

type Service struct {
	AuditLog     AuditLogger
	MutationLock func() Locker
	Runtime      *productruntime.Runtime
	// NetworkGenesisHashes maps every network the signer knows, built-in or
	// configured, to its base64 genesis hash. Rotating key generation uses it
	// to accept a network name such as "localnet".
	NetworkGenesisHashes func() map[string]string
}

type GenerateGenericLSigFunc func(context.Context, *productruntime.Runtime, string, map[string]string) (string, error)

// resolvedCreation is a creation request after its references are resolved and
// its instance selected.
type resolvedCreation struct {
	keyType  string
	params   map[string]string
	instance *lsigprovider.Instance
	// perKey is set for a type whose contract varies by account (the general
	// type and the plain hosts), which the boundary requirements govern.
	perKey bool
}

// resolveCreation runs the checks generation and preparation share, so a
// reviewed request cannot be judged differently from the one that follows it.
func (s Service) resolveCreation(keyType string, params map[string]string) (*resolvedCreation, *Error) {
	ir := s.Runtime
	keyType = keytypecatalog.Canonicalize(keyType)
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}
	if keyType == "" {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "key_type is required"}
	}
	if roleErr := keyclass.ValidateKeyTypeAllowedForNodeRole(ir.NodeRole(), keyType); roleErr != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: roleErr.Error()}
	}
	if rotatingkey.IsRotatingKeyType(keyType) {
		params = s.resolveRotatingNetwork(params)
	}
	if provider := lsigprovider.Get(keyType); provider != nil {
		if component, ok := lsigprovider.CosignerComponentKeyType(provider, params); ok {
			resolved, err := cosignerrefs.ResolveCreationParamsForComponent(ir.KeyPaths(), keyType, component, params)
			if err != nil {
				return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
			}
			params = resolved
		}
	}

	var instance *lsigprovider.Instance
	perKey := false
	if provider := lsigprovider.Get(keyType); provider != nil {
		_, perKey = provider.(lsigprovider.InstanceResolver)
		// Canonicalize at the admin boundary so persisted params and API responses
		// are stable; lower layers also normalize defensively.
		resolved, err := lsigprovider.ResolveInstance(provider, params)
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
		instance = resolved
		params = instance.Values
		if instance.Bounded != nil && instance.Bounded.Cosigner != nil {
			if err := validateVisibleCosignerAuthorityCollisions(ir, params[boundedmeta.CosignerPublicKeyParameter]); err != nil {
				return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
			}
		}
	}
	return &resolvedCreation{keyType: keyType, params: params, instance: instance, perKey: perKey}, nil
}

// ReviewedValues are what PrepareGenerateKey returned for the request an operator
// reviewed. They are comparison values, not authorizations: approval and every
// other check apply whether or not a request carries them.
type ReviewedValues struct {
	Fingerprint    string
	BoundaryDigest string
}

// GenerateKey creates a key with no prior review. See GenerateReviewedKey.
func (s Service) GenerateKey(ctx context.Context, keyType string, params map[string]string, generateGenericLSig GenerateGenericLSigFunc) (*GenerateResult, *Error) {
	return s.GenerateReviewedKey(ctx, keyType, params, ReviewedValues{}, generateGenericLSig)
}

// GenerateReviewedKey creates a key. A mismatch with reviewed means the definition
// or the resolved request changed after the operator reviewed it.
func (s Service) GenerateReviewedKey(ctx context.Context, keyType string, params map[string]string, reviewed ReviewedValues, generateGenericLSig GenerateGenericLSigFunc) (*GenerateResult, *Error) {
	ir := s.Runtime
	if ctx == nil {
		ctx = context.Background()
	}
	creation, resolveErr := s.resolveCreation(keyType, params)
	if resolveErr != nil {
		return nil, resolveErr
	}
	keyType, params = creation.keyType, creation.params

	unlockMutation, lockErr := s.lockUnlockedMutation()
	if lockErr != nil {
		return nil, lockErr
	}
	defer unlockMutation()
	activeKeyPaths, activeErr := ir.ActiveKeyPaths()
	if activeErr != nil {
		return nil, mapGenerateError(activeErr)
	}

	activated, activationErr := activatedKeyTypes(activeKeyPaths)
	if activationErr != nil {
		return nil, activationErr
	}
	if err := checkGenerationAllowed(activeKeyPaths, keyType); err != nil {
		return nil, err
	}
	if err := s.checkBoundaryRequirements(creation); err != nil {
		return nil, err
	}
	if err := checkReviewedValues(keyType, params, reviewed); err != nil {
		return nil, err
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

	mut := storemut.New(activeKeyPaths)
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
		s.AuditLog.LogKeyGenerated(ctx, genResult.Address, genResult.KeyType)
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

// resolveRotatingNetwork replaces a configured network name in the network
// parameter with that network's genesis hash. The generator itself knows only
// the built-in names, because it cannot see signer configuration.
// unavailableKeyTypeError explains why keyType cannot create keys on this
// node. A key type the binary carries, or a template the store has installed,
// names the step that enables it; any other key type is unknown here. Only
// the protocol-native key types are enabled by default.
// checkGenerationAllowed decides whether keyType may create an account. It must
// run under the mutation lock, on every creation route.
func checkGenerationAllowed(paths storepaths.Paths, keyType string) *Error {
	canGenerate, err := keytypestate.CanGenerate(paths, keyType)
	if err != nil {
		return &Error{Kind: ErrorInternal, Message: "failed to read key type state"}
	}
	if !canGenerate {
		return unavailableKeyTypeError(paths, keyType)
	}
	return nil
}

// checkReviewedValues recomputes what a review saw. Called under the lock, which
// also guards template changes.
func checkReviewedValues(keyType string, params map[string]string, reviewed ReviewedValues) *Error {
	if reviewed == (ReviewedValues{}) {
		return nil
	}
	changed := &Error{Kind: ErrorInvalidInput, Message: fmt.Sprintf("key type %s changed after this request was reviewed; review it again", keyType)}
	provider := lsigprovider.Get(keyType)
	if provider == nil {
		return changed
	}
	instance, err := lsigprovider.ResolveInstance(provider, params)
	if err != nil {
		return &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	}
	if reviewed.Fingerprint != "" && reviewed.Fingerprint != instance.ReviewFingerprint {
		return changed
	}
	if reviewed.BoundaryDigest != "" && reviewed.BoundaryDigest != instance.BoundaryDigest {
		return changed
	}
	return nil
}

// checkBoundaryRequirements applies the signer's generation settings to every
// per-key type, the general type and the plain hosts: an account whose
// parameters choose its contract. The plain program has no overlay contract, so
// it is neither contained nor cosigned. Expert templates, whose program the
// operator installed, and every other type pass through.
func (s Service) checkBoundaryRequirements(creation *resolvedCreation) *Error {
	if creation == nil || !creation.perKey {
		return nil
	}
	var metadata *boundedmeta.Metadata
	if creation.instance != nil {
		metadata = creation.instance.Bounded
	}
	requireContained, requireCosigner := s.Runtime.Config().BoundaryRequirements()
	if requireContained && (metadata == nil || !metadata.Contained()) {
		return &Error{Kind: ErrorInvalidInput, Message: "this signer requires new accounts to pay only listed recipients and to refuse rekeys or take only listed ones (boundary_require_contained)"}
	}
	if requireCosigner && (metadata == nil || metadata.Cosigner == nil) {
		return &Error{Kind: ErrorInvalidInput, Message: "this signer requires new accounts to have a cosigner (boundary_require_cosigner)"}
	}
	return nil
}

func unavailableKeyTypeError(paths storepaths.Paths, keyType string) *Error {
	if keytypecatalog.IsInternalOnly(keyType) {
		return &Error{Kind: ErrorInvalidInput, Message: fmt.Sprintf(
			"key type %s is internal-only; use a native key type for a standalone account or select an enabled composed key type", keyType)}
	}
	rec, recorded, err := keytypestate.Get(paths, keyType)
	if err == nil && (keytypecatalog.IsLibraryVisible(keyType) || (recorded && rec.State != keytypestate.StateEnabled)) {
		return &Error{Kind: ErrorInvalidInput, Message: fmt.Sprintf(
			"key type %s is not enabled on this node; enable it with `apadmin keytype enable %s` or in the apadmin KeyType Library",
			keyType, keyType)}
	}
	return &Error{Kind: ErrorInvalidInput, Message: fmt.Sprintf("invalid key type: %s", keyType)}
}

func (s Service) resolveRotatingNetwork(params map[string]string) map[string]string {
	name := strings.TrimSpace(params[rotatingkey.RotatingNetworkParameter])
	if name == "" || s.NetworkGenesisHashes == nil {
		return params
	}
	hash, ok := s.NetworkGenesisHashes()[name]
	if !ok {
		return params
	}
	resolved := make(map[string]string, len(params))
	for k, v := range params {
		resolved[k] = v
	}
	resolved[rotatingkey.RotatingNetworkParameter] = hash
	return resolved
}

func validateVisibleCosignerAuthorityCollisions(ir *productruntime.Runtime, cosignerPublicKeyHex string) error {
	if ir == nil || ir.KeyStore() == nil {
		return nil
	}
	normalized := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cosignerPublicKeyHex), "0x")))
	if normalized == "" {
		return nil
	}
	for selector, publicKeyHex := range ir.KeyStore().GetPublicKeyHexMap() {
		if strings.ToLower(strings.TrimSpace(publicKeyHex)) == normalized {
			return fmt.Errorf("bounded cosigner public key collides with signer-managed key %s", selector)
		}
	}
	return nil
}

func (s Service) DeleteKey(ctx context.Context, address string) (*DeleteResult, *Error) {
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

	unlockMutation, lockErr := s.lockUnlockedMutation()
	if lockErr != nil {
		return nil, lockErr
	}
	defer unlockMutation()
	activeKeyPaths, activeErr := ir.ActiveKeyPaths()
	if activeErr != nil {
		return nil, mapGenerateError(activeErr)
	}

	keyFile, err := ir.FindKeyFile(address)
	if err != nil {
		return nil, &Error{Kind: ErrorNotFound, Message: "key not found: " + address}
	}
	delResult, err := storemut.New(activeKeyPaths).DeleteKey(address, keyFile)
	if err != nil {
		return nil, &Error{Kind: ErrorInternal, Message: "key deletion failed: " + err.Error()}
	}
	if reloadErr := reloadKeys(ir); reloadErr != nil {
		return nil, reloadErr
	}
	// A rotating account's stage address table is a cache derived from the
	// key that just left; it goes with it. The key is already out of the
	// published inventory, so a fill racing this deletion is refused when it
	// asks for the table. Nothing depends on the table, so a failure here is
	// reported, not fatal.
	if tables := ir.StageTables(); tables != nil && storepaths.ValidateStageSelector(address) == nil {
		if tableErr := tables.Delete(address); tableErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: key %s was deleted but its stage table was not: %v\n", address, tableErr)
		}
	}

	if s.AuditLog != nil {
		s.AuditLog.LogKeyDeleted(ctx, address, delResult.DeletedPath)
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

// lockUnlockedMutation takes the store mutation lock for an in-place write to
// the selected generation and rechecks, under the lock, that the runtime is
// still unlocked. A caller's earlier check is not enough: a request queued
// behind a generation commit can resume after that commit failed and set
// recovery, when the runtime may still be bound to the superseded, sealed
// generation.
func (s Service) lockUnlockedMutation() (func(), *Error) {
	unlock := s.lockMutation()
	if s.Runtime != nil && !s.Runtime.IsUnlocked() {
		unlock()
		return nil, &Error{Kind: ErrorLocked, Message: "signer is not unlocked"}
	}
	return unlock, nil
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
