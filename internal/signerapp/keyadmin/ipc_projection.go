// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// ProjectGenerateIPC discards the generated mnemonic by design: recovery
// material does not cross the admin-protocol boundary. Use encrypted backups
// for recovery.
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
		Parameters:               result.Parameters,
		DisplayTEAL:              result.DisplayTEAL,
		TemplateProvenanceStatus: result.TemplateProvenanceStatus,
		TemplateProvenanceNote:   result.TemplateProvenanceNote,
	}
}

func keyDetailsIPCCode(err *Error) string {
	if err.Kind == ErrorNotFound {
		return protocol.ErrCodeKeyNotFound
	}
	return protocol.IPCErrorCode(err.Message)
}

func ProjectImportIPC(result *keymgmt.ImportResult, keyType string, err *Error) adminproto.ImportKeyResult {
	if err != nil {
		return adminproto.ImportKeyResult{
			Success: false,
			Code:    protocol.IPCErrorCode(err.Message),
			Error:   err.Message,
		}
	}
	return adminproto.ImportKeyResult{
		Success: true,
		Address: result.Address,
		KeyType: keyType,
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
