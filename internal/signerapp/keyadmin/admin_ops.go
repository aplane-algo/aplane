// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"fmt"
	"maps"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"

	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypeux"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"
	"github.com/aplane-algo/aplane/internal/witness"
)

func (s Service) ListKeys() ([]adminproto.KeyInfo, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}

	keysSnapshot, _ := ir.KeySnapshot()
	keysList := make([]adminproto.KeyInfo, 0, len(keysSnapshot))

	// Every listed key was validated when the generation loaded, so a key that
	// no longer reads is an integrity failure to report, not an unknown type.
	err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		for addr, keyFile := range keysSnapshot {
			info, err := keymgmt.DetectKeyInfoFromFileWithKeyring(keyFile, mk)
			if err != nil {
				return fmt.Errorf("read key %s: %w", addr, err)
			}
			templateProvenanceStatus, templateProvenanceNote := lsigprovider.CompareAccountProvenance(info.Type, info.TemplateFingerprint, info.Parameters, info.BoundedAuthorization)
			keysList = append(keysList, adminproto.KeyInfo{
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

func (s Service) GetKeyDetails(address string) (*adminproto.GetKeyDetailsResult, *Error) {
	ir := s.Runtime
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "product runtime is nil"}
	}

	keyFile, err := ir.FindKeyFile(address)
	if err != nil {
		return nil, &Error{Kind: ErrorNotFound, Message: "key not found"}
	}

	result := &adminproto.GetKeyDetailsResult{Address: address}
	err = ir.WithKeyring(func(mk *crypto.Keyring) error {
		info, err := keymgmt.DetectKeyInfoFromFileWithKeyring(keyFile, mk)
		if err != nil {
			return fmt.Errorf("read key %s: %w", address, err)
		}
		result.KeyType = info.Type
		if witness.IsKeyType(info.Type) {
			result.PublicKeyHex = info.PublicKeyHex
		}
		result.Parameters = keyDetailsParameters(info.Parameters, info.BoundedAuthorization)
		result.TemplateProvenanceStatus, result.TemplateProvenanceNote = lsigprovider.CompareAccountProvenance(info.Type, info.TemplateFingerprint, info.Parameters, info.BoundedAuthorization)
		result.PolicyLabel = keytypeux.BoundedMetadataLabel(info.BoundedAuthorization)
		result.DisplayTEAL = info.DisplayTEAL
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

// ImportKey imports a key from a recovery phrase. The caller owns mnemonic and
// zeroes it after the call. The key generators and algosdk take the phrase as
// a string, so an import that passes the checks below leaves one string copy
// that cannot be zeroed (see "Residual Copies" in ARCH_SECURITY.md).
func (s Service) ImportKey(ctx context.Context, keyType string, mnemonic []byte, params map[string]string) (*keymgmt.ImportResult, *Error) {
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

	activated, activationErr := activatedKeyTypes(activeKeyPaths)
	if activationErr != nil {
		return nil, activationErr
	}
	if err := checkGenerationAllowed(activeKeyPaths, keyType); err != nil {
		return nil, err
	}
	// This refuses every LogicSig key type, so import has no LogicSig
	// parameters to canonicalize.
	if !keymgmt.SupportsMnemonicImport(keyType) {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "mnemonic import not supported for key type: " + keyType}
	}

	mut := storemut.New(activeKeyPaths)
	var importResult *keymgmt.ImportResult
	err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		var importErr error
		importResult, importErr = mut.ImportKeyFromMnemonicWithActivatedContext(ctx, keyType, string(mnemonic), mk, params, activated)
		return importErr
	})
	if err != nil {
		return nil, mapGenerateError(err)
	}

	// The key is written and stays written, whatever the reload after it
	// finds, so its audit event is recorded first, and a failed reload is
	// answered with the result beside it.
	if s.AuditLog != nil {
		s.AuditLog.LogKeyImported(ctx, importResult.Address, keyType)
	}
	if reloadErr := reloadKeys(ir); reloadErr != nil {
		return importResult, reloadErr
	}
	return importResult, nil
}
