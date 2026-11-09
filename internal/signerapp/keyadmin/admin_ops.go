// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"fmt"
	"maps"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"

	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/keytypeux"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"
	"github.com/aplane-algo/aplane/internal/witness"
)

func (s Service) ListKeys() ([]ListKeyInfo, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}

	keysSnapshot, _ := ir.KeySnapshot()
	keysList := make([]ListKeyInfo, 0, len(keysSnapshot))

	// Every listed key was validated when the generation loaded, so a key that
	// no longer reads is an integrity failure to report, not an unknown type.
	err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		for addr, keyFile := range keysSnapshot {
			info, err := keymgmt.DetectKeyInfoFromFileWithKeyring(keyFile, mk)
			if err != nil {
				return fmt.Errorf("read key %s: %w", addr, err)
			}
			templateProvenanceStatus, templateProvenanceNote := lsigprovider.CompareAccountProvenance(info.Type, info.TemplateFingerprint, info.Parameters, info.BoundedAuthorization)
			keysList = append(keysList, ListKeyInfo{
				Address:                  addr,
				KeyType:                  info.Type,
				TemplateProvenanceStatus: templateProvenanceStatus,
				TemplateProvenanceNote:   templateProvenanceNote,
			})
		}
		return nil
	})
	if err != nil {
		return nil, &Error{Kind: ErrorInternal, Message: err.Error()}
	}

	return keysList, nil
}

func (s Service) GetKeyDetails(address string) (*KeyDetailsResult, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}

	keyFile, err := ir.FindKeyFile(address)
	if err != nil {
		return nil, &Error{Kind: ErrorNotFound, Message: "key not found"}
	}

	result := &KeyDetailsResult{Address: address}
	err = ir.WithKeyring(func(mk *crypto.Keyring) error {
		info, err := keymgmt.DetectKeyInfoFromFileWithKeyring(keyFile, mk)
		if err != nil {
			return fmt.Errorf("read key %s: %w", address, err)
		}
		result.KeyType = info.Type
		result.MnemonicExportable = info.MnemonicExportable
		if witness.IsKeyType(info.Type) {
			result.PublicKeyHex = info.PublicKeyHex
		}
		result.Parameters = keyDetailsParameters(info.Parameters, info.BoundedAuthorization)
		result.TemplateProvenanceStatus, result.TemplateProvenanceNote = lsigprovider.CompareAccountProvenance(info.Type, info.TemplateFingerprint, info.Parameters, info.BoundedAuthorization)
		result.PolicyLabel = keytypeux.BoundedMetadataLabel(info.BoundedAuthorization)
		if result.DisplayTEAL, err = keymgmt.GetDisplayTEALWithKeyring(keyFile, mk); err != nil {
			return fmt.Errorf("read TEAL for key %s: %w", address, err)
		}
		return nil
	})
	if err != nil {
		return nil, &Error{Kind: ErrorInternal, Message: err.Error()}
	}

	return result, nil
}

// keyDetailsCosignerParameter carries a cosigned account's cosigner in its
// details. It is the plain hosts' cosigner parameter, which takes a Witness Key
// ID, so the details show the cosigner the way an operator names it.
const keyDetailsCosignerParameter = "cosigner"

// keyDetailsParameters shows a cosigned account's cosigner by its Witness Key ID,
// the name an operator compares with the cosigner node, instead of the raw
// public key, which identifies nothing at a glance. The ID is checked against
// the public key when the key loads.
func keyDetailsParameters(parameters map[string]string, metadata *boundedmeta.Metadata) map[string]string {
	projected := maps.Clone(parameters)
	if metadata == nil || metadata.Cosigner == nil || metadata.Cosigner.ComponentKeyID == "" {
		return projected
	}
	delete(projected, boundedmeta.CosignerPublicKeyParameter)
	projected[keyDetailsCosignerParameter] = metadata.Cosigner.ComponentKeyID
	return projected
}

func (s Service) ImportKey(ctx context.Context, keyType, mnemonic string, params map[string]string) (*keymgmt.ImportResult, *Error) {
	ir := s.Runtime
	keyType = keytypecatalog.Canonicalize(keyType)
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}
	if roleErr := keyclass.ValidateKeyTypeAllowedForNodeRole(ir.NodeRole(), keyType); roleErr != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: roleErr.Error()}
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

	if provider := lsigprovider.Get(keyType); provider != nil {
		// Canonicalize at the admin boundary so persisted params and API responses
		// are stable; lower layers also normalize defensively.
		normalized, err := lsigprovider.NormalizeCreationParams(params, provider.CreationParams())
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
		params = normalized
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
		return nil, unavailableKeyTypeError(activeKeyPaths, keyType)
	}
	if !keymgmt.SupportsMnemonicImport(keyType) {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "mnemonic import not supported for key type: " + keyType}
	}

	mut := storemut.New(activeKeyPaths)
	var importResult *keymgmt.ImportResult
	err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		var importErr error
		importResult, importErr = mut.ImportKeyFromMnemonicWithActivated(keyType, mnemonic, mk, params, activated)
		return importErr
	})
	if err != nil {
		return nil, mapGenerateError(err)
	}

	if reloadErr := reloadKeys(ir); reloadErr != nil {
		return nil, reloadErr
	}

	if s.AuditLog != nil {
		s.AuditLog.LogKeyImported(ctx, importResult.Address, keyType)
	}
	return importResult, nil
}
