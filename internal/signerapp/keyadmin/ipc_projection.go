// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// ProjectGenerateIPC omits recovery material. Native mnemonic export is a
// separate authenticated operation; other key classes use encrypted backups.
func ProjectGenerateIPC(result *GenerateResult, err *Error) adminproto.GenerateKeyResult {
	if err != nil {
		return adminproto.GenerateKeyResult{
			Success: false,
			Code:    generateIPCCode(err),
			Error:   err.Message,
		}
	}

	return adminproto.GenerateKeyResult{
		Success:    true,
		Address:    result.Address,
		KeyType:    result.KeyType,
		Parameters: result.Parameters,
	}
}

// ProjectPrepareGenerateIPC maps a prepared request to the admin-domain result.
func ProjectPrepareGenerateIPC(prepared *PreparedGeneration, err *Error) adminproto.PrepareGenerateKeyResult {
	if err != nil {
		return adminproto.PrepareGenerateKeyResult{Code: generateIPCCode(err), Error: err.Message}
	}
	result := adminproto.PrepareGenerateKeyResult{
		Success:           true,
		KeyType:           prepared.KeyType,
		BaseKeyType:       prepared.BaseKeyType,
		Parameters:        prepared.Parameters,
		Fingerprint:       prepared.Fingerprint,
		ReviewFingerprint: prepared.ReviewFingerprint,
		BoundaryDigest:    prepared.BoundaryDigest,
		CosignerKeyID:     prepared.CosignerKeyID,
	}
	if metadata := prepared.Bounded; metadata != nil {
		profile := &adminproto.PreparedBoundedProfile{
			Contract:         metadata.Contract,
			SpendEffects:     metadata.SpendEffects,
			MaxFee:           boundedmeta.CloneMaxFee(metadata.MaxFee),
			Rekey:            string(metadata.Rekey),
			RekeyList:        metadata.RekeyList != nil,
			Layer3Policy:     metadata.Layer3Policy,
			CosignerRequired: metadata.Cosigner != nil,
		}
		result.Bounded = profile
	}
	return result
}

func ProjectDeleteIPC(err *Error) adminproto.DeleteKeyResult {
	if err != nil {
		return adminproto.DeleteKeyResult{
			Success: false,
			Code:    deleteIPCCode(err),
			Error:   deleteIPCMessage(err),
		}
	}
	return adminproto.DeleteKeyResult{Success: true}
}

func ProjectListKeys(keys []ListKeyInfo, err *Error) ([]adminproto.KeyInfo, error) {
	if err != nil {
		return nil, err
	}
	result := make([]adminproto.KeyInfo, 0, len(keys))
	for _, key := range keys {
		result = append(result, adminproto.KeyInfo{
			Address:                  key.Address,
			KeyType:                  key.KeyType,
			TemplateProvenanceStatus: key.TemplateProvenanceStatus,
			TemplateProvenanceNote:   key.TemplateProvenanceNote,
		})
	}
	return result, nil
}

func ProjectKeyDetailsIPC(result *KeyDetailsResult, err *Error) adminproto.GetKeyDetailsResult {
	if err != nil {
		return adminproto.GetKeyDetailsResult{
			Success: false,
			Code:    keyDetailsIPCCode(err),
			Error:   err.Message,
		}
	}
	return adminproto.GetKeyDetailsResult{
		Success:                  true,
		Address:                  result.Address,
		KeyType:                  result.KeyType,
		PublicKeyHex:             result.PublicKeyHex,
		Parameters:               result.Parameters,
		DisplayTEAL:              result.DisplayTEAL,
		TemplateProvenanceStatus: result.TemplateProvenanceStatus,
		TemplateProvenanceNote:   result.TemplateProvenanceNote,
		PolicyLabel:              result.PolicyLabel,
		MnemonicExportable:       result.MnemonicExportable,
	}
}

func keyDetailsIPCCode(err *Error) string {
	return ipcCodeForErrorKind(err)
}

func ProjectImportIPC(result *keymgmt.ImportResult, err *Error) adminproto.ImportKeyResult {
	if err != nil {
		return adminproto.ImportKeyResult{
			Success: false,
			Code:    ipcCodeForErrorKind(err),
			Error:   err.Message,
		}
	}
	return adminproto.ImportKeyResult{
		Success: true,
		Address: result.Address,
		KeyType: result.KeyType,
	}
}

func generateIPCCode(err *Error) string {
	switch err.Kind {
	case ErrorInvalidInput:
		return protocol.ErrCodeInvalidRequest
	case ErrorInvalidPassphrase:
		return protocol.ErrCodeInvalidPassphrase
	case ErrorLocked:
		return protocol.ErrCodeSignerLocked
	default:
		return protocol.ErrCodeInternal
	}
}

func deleteIPCCode(err *Error) string {
	return ipcCodeForErrorKind(err)
}

func ipcCodeForErrorKind(err *Error) string {
	switch err.Kind {
	case ErrorInvalidInput:
		return protocol.ErrCodeInvalidRequest
	case ErrorInvalidPassphrase:
		return protocol.ErrCodeInvalidPassphrase
	case ErrorLocked:
		return protocol.ErrCodeSignerLocked
	case ErrorNotFound:
		return protocol.ErrCodeKeyNotFound
	default:
		return protocol.ErrCodeInternal
	}
}

func deleteIPCMessage(err *Error) string {
	if err == nil {
		return ""
	}
	if err.Kind == ErrorNotFound {
		return "Key not found: " + trimKeyNotFoundPrefix(err.Message)
	}
	return err.Message
}

func trimKeyNotFoundPrefix(msg string) string {
	const prefix = "key not found: "
	if strings.HasPrefix(msg, prefix) {
		return strings.TrimPrefix(msg, prefix)
	}
	return msg
}
