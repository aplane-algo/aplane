// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// ProjectGenerateIPC omits recovery material. Native mnemonic export is a
// separate authenticated operation; other key classes use encrypted backups.
// A failure with a result beside it is a reload's after the key was written:
// the reply names the key.
func ProjectGenerateIPC(result *GenerateResult, err *Error) adminproto.GenerateKeyResult {
	if err != nil {
		failed := adminproto.GenerateKeyResult{
			Success: false,
			Code:    ipcCodeForErrorKind(err),
			Error:   err.Message,
		}
		if result != nil {
			failed.Address, failed.KeyType = result.Address, result.KeyType
		}
		return failed
	}

	return adminproto.GenerateKeyResult{
		Success:    true,
		Address:    result.Address,
		KeyType:    result.KeyType,
		Parameters: result.Parameters,
		Warnings:   result.Warnings,
	}
}

// ProjectPrepareGenerateIPC maps a prepared request to the admin-domain result.
func ProjectPrepareGenerateIPC(prepared *PreparedGeneration, err *Error) adminproto.PrepareGenerateKeyResult {
	if err != nil {
		return adminproto.PrepareGenerateKeyResult{Code: ipcCodeForErrorKind(err), Error: err.Message}
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
		Warnings:          prepared.Warnings,
	}
	if metadata := prepared.Bounded; metadata != nil {
		profile := &adminproto.PreparedHostProfile{
			Rekey:            string(metadata.Rekey),
			RekeyList:        metadata.RekeyList != nil,
			CosignerRequired: metadata.Cosigner != nil,
		}
		if bounds := metadata.Bounds; bounds != nil {
			profile.Bounds = &adminproto.PreparedHostBounds{
				SpendEffects: append([]string{}, bounds.SpendEffects...),
				Layer3Policy: bounds.Layer3Policy,
			}
			// Prepared metadata always has a ceiling; without one this shows 0.
			if bounds.MaxFee != nil {
				profile.Bounds.MaxFee = *bounds.MaxFee
			}
		}
		if metadata.Cosigner != nil {
			profile.CosignerKeyType = metadata.Cosigner.ComponentKeyType
		}
		result.Host = profile
	}
	return result
}

func ProjectDeleteIPC(err *Error) adminproto.DeleteKeyResult {
	if err != nil {
		return adminproto.DeleteKeyResult{
			Success: false,
			Code:    ipcCodeForErrorKind(err),
			Error:   deleteIPCMessage(err),
		}
	}
	return adminproto.DeleteKeyResult{Success: true}
}

// ProjectListKeys returns err as an error only when there is one.
func ProjectListKeys(keys []adminproto.KeyInfo, err *Error) ([]adminproto.KeyInfo, error) {
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func ProjectKeyDetailsIPC(result *adminproto.GetKeyDetailsResult, err *Error) adminproto.GetKeyDetailsResult {
	if err != nil {
		return adminproto.GetKeyDetailsResult{
			Success: false,
			Code:    ipcCodeForErrorKind(err),
			Error:   err.Message,
		}
	}
	details := *result
	details.Success = true
	return details
}

// ProjectImportIPC names the imported key in a failure with a result beside
// it, a reload's after the key was written, as ProjectGenerateIPC does.
func ProjectImportIPC(result *keymgmt.ImportResult, err *Error) adminproto.ImportKeyResult {
	if err != nil {
		failed := adminproto.ImportKeyResult{
			Success: false,
			Code:    ipcCodeForErrorKind(err),
			Error:   err.Message,
		}
		if result != nil {
			failed.Address, failed.KeyType = result.Address, result.KeyType
		}
		return failed
	}
	return adminproto.ImportKeyResult{
		Success: true,
		Address: result.Address,
		KeyType: result.KeyType,
	}
}

func ipcCodeForErrorKind(err *Error) string {
	switch err.Kind {
	case ErrorInvalidInput:
		return protocol.ErrCodeInvalidRequest
	case ErrorInvalidPassphrase:
		return protocol.ErrCodeInvalidPassphrase
	case ErrorLocked:
		return protocol.ErrCodeSignerLocked
	case ErrorRecoveryBlocked:
		return protocol.ResultCodeRecoveryBlocked
	case ErrorNotFound:
		return protocol.ErrCodeKeyNotFound
	case ErrorSourceTokenNotSet:
		return protocol.ErrCodeSourceTokenNotSet
	default:
		return protocol.ErrCodeInternal
	}
}

func deleteIPCMessage(err *Error) string {
	if err.Kind == ErrorNotFound {
		return "Key not found: " + strings.TrimPrefix(err.Message, "key not found: ")
	}
	return err.Message
}
