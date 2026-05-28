// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// LSigFile represents the on-disk format for a generic LogicSig file.
// Files are encrypted using AES-256-GCM to prevent tampering (e.g., swapping recipient addresses).
// All key types (DSA and LogicSig) use the unified .key extension.
type LSigFile struct {
	FormatVersion          int                `json:"format_version"` // Key file format version
	Category               string             `json:"category"`       // Always "generic_lsig" for this file type
	Address                string             `json:"address"`
	KeyType                string             `json:"key_type"`              // e.g., "aplane.timelock.v1"
	Template               string             `json:"template,omitempty"`    // Template name (e.g., "timelock")
	Parameters             map[string]string  `json:"parameters,omitempty"`  // Template parameters
	BytecodeHex            string             `json:"bytecode_hex"`          // Hex-encoded TEAL bytecode
	SaltCounter            byte               `json:"salt_counter"`          // Salt byte used to force an off-curve LogicSig address
	TEALSource             string             `json:"teal_source,omitempty"` // Original TEAL source (for documentation)
	SigningMetadataVersion int                `json:"signing_metadata_version,omitempty"`
	SigningArgs            []StoredSigningArg `json:"signing_args,omitempty"`
	TemplateFingerprint    string             `json:"template_fingerprint,omitempty"`
	CreatedAt              string             `json:"created_at,omitempty"` // RFC 3339 creation timestamp
}

// WriteLSigFile writes an encrypted LogicSig file to disk.
// Uses master key encryption (AES-256-GCM) to prevent tampering.
// identityID scopes the key to a specific identity directory.
// masterKey should be the derived encryption key from the keystore (not raw passphrase).
// tealSource is the original TEAL source code for documentation purposes.
func WriteLSigFile(paths storepaths.Paths, identityID, address, keyType, template string, parameters map[string]string, bytecode []byte, saltCounter byte, tealSource string, signingArgs []StoredSigningArg, masterKey []byte) error {
	lsigFile := LSigFile{
		FormatVersion:          CurrentKeyFormatVersion,
		Category:               CategoryGenericLsig,
		Address:                address,
		KeyType:                keyType,
		Template:               template,
		Parameters:             parameters,
		BytecodeHex:            hex.EncodeToString(bytecode),
		SaltCounter:            saltCounter,
		TEALSource:             tealSource,
		SigningMetadataVersion: CurrentSigningMetadataVersion,
		SigningArgs:            signingArgs,
		TemplateFingerprint:    TemplateFingerprintForKeyType(keyType),
		CreatedAt:              time.Now().UTC().Format(time.RFC3339),
	}

	// Marshal to JSON
	plaintext, err := json.MarshalIndent(lsigFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal lsig file: %w", err)
	}

	// Encrypt with master key
	encrypted, err := crypto.EncryptWithMasterKey(plaintext, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt lsig file: %w", err)
	}

	// Ensure identity-scoped directory exists
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	filePath := paths.KeyFilePath(identityID, address)

	// Write with group-accessible permissions
	if err := fsutil.WriteFile(filePath, encrypted); err != nil {
		return fmt.Errorf("failed to write lsig file: %w", err)
	}

	return nil
}

func (lf *LSigFile) UnmarshalJSON(data []byte) error {
	fields, err := parseKeyPayloadFields(data)
	if err != nil {
		return err
	}
	parameters, err := normalizedParameterFields(fields)
	if err != nil {
		return err
	}
	bytecodeHex, err := normalizedBytecodeHexFields(fields)
	if err != nil {
		return err
	}
	var aux struct {
		FormatVersion          int                `json:"format_version"`
		Category               string             `json:"category"`
		Address                string             `json:"address"`
		KeyType                string             `json:"key_type"`
		Template               string             `json:"template,omitempty"`
		SaltCounter            *byte              `json:"salt_counter"`
		TEALSource             string             `json:"teal_source,omitempty"`
		SigningMetadataVersion int                `json:"signing_metadata_version,omitempty"`
		SigningArgs            []StoredSigningArg `json:"signing_args,omitempty"`
		TemplateFingerprint    string             `json:"template_fingerprint,omitempty"`
		CreatedAt              string             `json:"created_at,omitempty"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.SaltCounter == nil {
		return ErrMissingLogicSigSaltCounter
	}
	*lf = LSigFile{
		FormatVersion:          aux.FormatVersion,
		Category:               aux.Category,
		Address:                aux.Address,
		KeyType:                aux.KeyType,
		Template:               aux.Template,
		Parameters:             parameters,
		BytecodeHex:            bytecodeHex,
		SaltCounter:            *aux.SaltCounter,
		TEALSource:             aux.TEALSource,
		SigningMetadataVersion: aux.SigningMetadataVersion,
		SigningArgs:            aux.SigningArgs,
		TemplateFingerprint:    aux.TemplateFingerprint,
		CreatedAt:              aux.CreatedAt,
	}
	return nil
}

// IsGenericLSigType checks if a key type is a generic LogicSig (not DSA-based).
// This delegates to the genericlsig registry for proper self-registration support.
func IsGenericLSigType(keyType string) bool {
	return genericlsig.IsGenericLSigType(keyType)
}
