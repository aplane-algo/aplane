// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

import (
	"github.com/aplane-algo/aplane/internal/protocol"
)

// Re-export protocol message type constants for convenience within the tui package.
// This allows other files in this package to use these constants without the protocol prefix.
const (
	// Authentication message types
	MsgTypeAuthRequired = protocol.MsgTypeAuthRequired
	MsgTypeAuth         = protocol.MsgTypeAuth
	MsgTypeAuthResult   = protocol.MsgTypeAuthResult

	// Signer state message types
	MsgTypeUnlock       = protocol.MsgTypeUnlock
	MsgTypeUnlockResult = protocol.MsgTypeUnlockResult
	MsgTypeSignRequest  = protocol.MsgTypeSignRequest
	MsgTypeSignResponse = protocol.MsgTypeSignResponse
	MsgTypeStatus       = protocol.MsgTypeStatus
	MsgTypeError        = protocol.MsgTypeError

	// Token provisioning message types
	MsgTypeTokenProvisioningRequest  = protocol.MsgTypeTokenProvisioningRequest
	MsgTypeTokenProvisioningResponse = protocol.MsgTypeTokenProvisioningResponse
	MsgTypeListKeys                  = protocol.MsgTypeListKeys
	MsgTypeKeysList                  = protocol.MsgTypeKeysList
	MsgTypeGenerateKey               = protocol.MsgTypeGenerateKey
	MsgTypeGenerateResult            = protocol.MsgTypeGenerateResult
	MsgTypeDeleteKey                 = protocol.MsgTypeDeleteKey
	MsgTypeDeleteResult              = protocol.MsgTypeDeleteResult
	MsgTypeExportKey                 = protocol.MsgTypeExportKey
	MsgTypeExportResult              = protocol.MsgTypeExportResult
	MsgTypeImportKey                 = protocol.MsgTypeImportKey
	MsgTypeImportResult              = protocol.MsgTypeImportResult
	MsgTypeGetKeyDetails             = protocol.MsgTypeGetKeyDetails
	MsgTypeKeyDetails                = protocol.MsgTypeKeyDetails

	// Server-initiated notification message types
	MsgTypeKeysChanged  = protocol.MsgTypeKeysChanged
	MsgTypeSignerLocked = protocol.MsgTypeSignerLocked

	// Client displacement message types
	MsgTypeClientExists    = protocol.MsgTypeClientExists
	MsgTypeDisplaceConfirm = protocol.MsgTypeDisplaceConfirm
	MsgTypeDisplaced       = protocol.MsgTypeDisplaced
)

// Type aliases for protocol message types (wire format types)
type (
	BaseMessage                      = protocol.BaseMessage
	AuthRequiredMessage              = protocol.AuthRequiredMessage
	AuthMessage                      = protocol.AuthMessage
	AuthResultMessage                = protocol.AuthResultMessage
	UnlockMessage                    = protocol.UnlockMessage
	UnlockResultMessage              = protocol.UnlockResultMessage
	SignRequestMessage               = protocol.SignRequestMessage
	SignResponseMessage              = protocol.SignResponseMessage
	StatusMessage                    = protocol.StatusMessage
	ErrorMessage                     = protocol.ErrorMessage
	ListKeysMessage                  = protocol.ListKeysMessage
	KeysListMessage                  = protocol.KeysListMessage
	GenerateKeyMessage               = protocol.GenerateKeyMessage
	GenerateResultMessage            = protocol.GenerateResultMessage
	DeleteKeyMessage                 = protocol.DeleteKeyMessage
	DeleteResultMessage              = protocol.DeleteResultMessage
	ExportKeyMessage                 = protocol.ExportKeyMessage
	ExportResultMessage              = protocol.ExportResultMessage
	ImportKeyMessage                 = protocol.ImportKeyMessage
	ImportResultMessage              = protocol.ImportResultMessage
	GetKeyDetailsMessage             = protocol.GetKeyDetailsMessage
	KeyDetailsMessage                = protocol.KeyDetailsMessage
	KeysChangedMessage               = protocol.KeysChangedMessage
	SignerLockedMessage              = protocol.SignerLockedMessage
	ClientExistsMessage              = protocol.ClientExistsMessage
	DisplaceConfirmMessage           = protocol.DisplaceConfirmMessage
	DisplacedMessage                 = protocol.DisplacedMessage
	TokenProvisioningRequestMessage  = protocol.TokenProvisioningRequestMessage
	TokenProvisioningResponseMessage = protocol.TokenProvisioningResponseMessage
)
