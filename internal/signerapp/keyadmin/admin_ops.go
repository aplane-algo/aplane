// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"encoding/hex"
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto"
	"maps"
	"strings"

	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/storemut"
	"github.com/aplane-algo/aplane/internal/witness"
)

func (s Service) ListKeys(ir *identity.Runtime) ([]ListKeyInfo, *Error) {
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "identity runtime is nil"}
	}

	keysSnapshot, _, _ := ir.KeySnapshot()
	keysList := make([]ListKeyInfo, 0, len(keysSnapshot))

	err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		for addr, keyFile := range keysSnapshot {
			keyType := "unknown"
			var templateProvenanceStatus, templateProvenanceNote string
			if info, err := keymgmt.DetectKeyInfoFromFileWithMasterKey(keyFile, mk); err == nil {
				keyType = info.Type
				templateProvenanceStatus, templateProvenanceNote = keys.CompareTemplateFingerprint(keyType, info.TemplateFingerprint)
			}
			keysList = append(keysList, ListKeyInfo{
				Address:                  addr,
				KeyType:                  keyType,
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

func (s Service) GetKeyDetails(ir *identity.Runtime, address string) (*KeyDetailsResult, *Error) {
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "identity runtime is nil"}
	}

	keyFile, err := ir.FindKeyFile(address)
	if err != nil {
		return nil, &Error{Kind: ErrorNotFound, Message: "key not found"}
	}

	result := &KeyDetailsResult{
		Address: address,
		KeyType: "unknown",
	}
	err = ir.WithKeyring(func(mk *crypto.Keyring) error {
		info, err := keymgmt.DetectKeyInfoFromFileWithMasterKey(keyFile, mk)
		if err == nil {
			result.KeyType = info.Type
			if witness.IsKeyType(info.Type) {
				result.PublicKeyHex = info.PublicKeyHex
			}
			result.Parameters = keyDetailsParameters(info.Type, info.Parameters)
			result.TemplateProvenanceStatus, result.TemplateProvenanceNote = keys.CompareTemplateFingerprint(info.Type, info.TemplateFingerprint)
			result.DisplayTEAL, _ = keymgmt.GetDisplayTEALWithMasterKey(keyFile, mk)
		}
		return nil
	})
	if err != nil {
		return nil, &Error{Kind: ErrorInternal, Message: err.Error()}
	}

	return result, nil
}

const keyDetailsSentryLabel = "Sentry"

func keyDetailsParameters(keyType string, parameters map[string]string) map[string]string {
	if !keytypes.IsGuardedAccountKeyType(keyType) {
		return maps.Clone(parameters)
	}

	projected := make(map[string]string)
	for key, value := range parameters {
		if key == keytypes.ParameterSentryPublicKey {
			continue
		}
		projected[key] = value
	}

	componentKey, err := sentryComponentSelectorForDetails(keyType, parameters[keytypes.ParameterSentryPublicKey])
	if err != nil {
		projected[keyDetailsSentryLabel] = fmt.Sprintf("invalid sentry public key (%v)", err)
		return projected
	}
	projected[keyDetailsSentryLabel] = componentKey
	return projected
}

func sentryComponentSelectorForDetails(keyType, publicKeyHex string) (string, error) {
	componentKeyType, ok := keytypes.SentryComponentKeyTypeForGuardedAccount(keyType)
	if !ok {
		return "", fmt.Errorf("unknown guarded account key type %q", keyType)
	}
	value := strings.TrimSpace(publicKeyHex)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	publicKey, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	return witness.ID(componentKeyType, publicKey)
}

func (s Service) ImportKey(ir *identity.Runtime, keyType, mnemonic string, params map[string]string) (*keymgmt.ImportResult, *Error) {
	keyType = keytypecatalog.Canonicalize(keyType)
	if ir == nil {
		return nil, &Error{Kind: ErrorInternal, Message: "identity runtime is nil"}
	}
	if roleErr := keyclass.ValidateKeyTypeAllowedForNodeRole(ir.NodeRole(), keyType); roleErr != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: roleErr.Error()}
	}

	unlockMutation := s.lockMutation(ir.ID())
	defer unlockMutation()

	if provider := lsigprovider.Get(keyType); provider != nil {
		// Canonicalize at the admin boundary so persisted params and API responses
		// are stable; lower layers also normalize defensively.
		normalized, err := lsigprovider.NormalizeCreationParams(params, provider.CreationParams())
		if err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
		params = normalized
	}

	activated, activationErr := activatedKeyTypes(ir)
	if activationErr != nil {
		return nil, activationErr
	}
	canGenerate, stateErr := keytypestate.CanGenerate(ir.KeyPaths(), ir.ID(), keyType)
	if stateErr != nil {
		return nil, &Error{Kind: ErrorInternal, Message: "failed to read key type state"}
	}
	if !canGenerate {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "invalid key type: " + keyType}
	}
	if !keymgmt.SupportsMnemonicImport(keyType) {
		return nil, &Error{Kind: ErrorInvalidInput, Message: "mnemonic import not supported for key type: " + keyType}
	}

	mut := storemut.New(ir.ID(), ir.KeyPaths(), nil, nil)
	var importResult *keymgmt.ImportResult
	err := ir.WithKeyring(func(mk *crypto.Keyring) error {
		var importErr error
		importResult, importErr = mut.ImportKeyFromMnemonicWithActivated(keyType, mnemonic, mk, params, activated)
		return importErr
	})
	if err != nil {
		return nil, mapGenerateError(err)
	}

	if reloadErr := reloadIdentityKeys(ir); reloadErr != nil {
		return nil, reloadErr
	}

	if s.AuditLog != nil {
		s.AuditLog.LogKeyImported(ir.ID(), importResult.Address, keyType)
	}
	return importResult, nil
}
