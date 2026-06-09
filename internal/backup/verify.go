// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// VerifyResult contains the result of verifying a single key file
type VerifyResult struct {
	Address  string
	FileName string
	Size     int64
	Valid    bool
	Error    string
	KeyType  string // Only set for deep verification
}

// VerifyReport contains the results of verifying a backup directory
type VerifyReport struct {
	BackupDir   string
	TotalFiles  int
	ValidFiles  int
	FailedFiles int
	Results     []VerifyResult
}

// DeepVerifyOptions controls optional backup checks that require external
// services or stricter archive semantics than regular restore needs.
type DeepVerifyOptions struct {
	// ValidateBundledTemplateBytecode recompiles any bundled LogicSig template
	// and verifies that it reproduces the key's stored LogicSig bytecode.
	ValidateBundledTemplateBytecode bool
	AlgodClient                     *algod.Client
	Context                         context.Context
}

// VerifyBackup performs basic validation of all .apb files in a backup directory
// Does not require passphrase - only checks file format
func VerifyBackup(backupDir string) (*VerifyReport, error) {
	// Scan for .apb files
	addresses, err := ScanBackupFiles(backupDir)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no .apb files found in %s", backupDir)
	}

	report := &VerifyReport{
		BackupDir: backupDir,
		Results:   make([]VerifyResult, 0, len(addresses)),
	}

	for _, address := range addresses {
		result := verifyFileBasic(backupDir, address)
		report.Results = append(report.Results, result)

		if result.Valid {
			report.ValidFiles++
		} else {
			report.FailedFiles++
		}
	}

	report.TotalFiles = len(report.Results)
	return report, nil
}

// verifyFileBasic performs basic validation without decryption
func verifyFileBasic(backupDir, address string) VerifyResult {
	result := VerifyResult{
		Address:  address,
		FileName: address + ".apb",
	}

	filePath := filepath.Join(backupDir, result.FileName)

	// Check file exists and get size
	info, err := os.Stat(filePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("file not found: %v", err)
		return result
	}
	result.Size = info.Size()

	// Check file is not empty
	if result.Size == 0 {
		result.Valid = false
		result.Error = "file is empty"
		return result
	}

	// Try to read and parse as JSON
	data, err := os.ReadFile(filePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return result
	}

	if !crypto.IsEncrypted(data) {
		result.Valid = false
		result.Error = "backup file must be encrypted"
		return result
	}
	var encrypted crypto.EncryptedData
	if err := json.Unmarshal(data, &encrypted); err != nil {
		result.Valid = false
		result.Error = "invalid encrypted data format"
		return result
	}
	if encrypted.EnvelopeVersion != 2 {
		result.Valid = false
		result.Error = fmt.Sprintf("unsupported envelope_version: %d", encrypted.EnvelopeVersion)
		return result
	}
	if encrypted.Salt == "" || encrypted.Nonce == "" || encrypted.Ciphertext == "" {
		result.Valid = false
		result.Error = "missing required encryption fields (standalone v2)"
		return result
	}

	result.Valid = true
	return result
}

// DeepVerifyBackup performs deep validation by decrypting and validating all key files.
// backupDir is the backup root (containing keys/ subdirectory).
// Requires the export passphrase used to create the standalone backup.
func DeepVerifyBackup(backupDir, passphrase string) (*VerifyReport, error) {
	return DeepVerifyBackupWithOptions(backupDir, passphrase, DeepVerifyOptions{})
}

// DeepVerifyBackupWithOptions performs deep validation by decrypting and validating
// all key files, with optional template-to-key bytecode validation.
func DeepVerifyBackupWithOptions(backupDir, passphrase string, opts DeepVerifyOptions) (*VerifyReport, error) {
	// Scan for .apb files in apb/ subdirectory
	keysDir := filepath.Join(backupDir, "apb")
	addresses, err := ScanBackupFiles(keysDir)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no .apb files found in %s", keysDir)
	}

	report := &VerifyReport{
		BackupDir: backupDir,
		Results:   make([]VerifyResult, 0, len(addresses)),
	}

	for _, address := range addresses {
		result := verifyFileDeep(keysDir, address, []byte(passphrase), opts)
		report.Results = append(report.Results, result)

		if result.Valid {
			report.ValidFiles++
		} else {
			report.FailedFiles++
		}
	}

	report.TotalFiles = len(report.Results)
	return report, nil
}

// verifyFileDeep performs deep validation by decrypting and parsing the key
func verifyFileDeep(backupDir, address string, passphrase []byte, opts DeepVerifyOptions) VerifyResult {
	result := VerifyResult{
		Address:  address,
		FileName: address + ".apb",
	}

	filePath := filepath.Join(backupDir, result.FileName)

	// Get file size
	info, err := os.Stat(filePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("file not found: %v", err)
		return result
	}
	result.Size = info.Size()

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to read file: %v", err)
		return result
	}

	if !crypto.IsEncrypted(data) {
		result.Valid = false
		result.Error = "backup file must be encrypted"
		return result
	}
	decryptedData, err := crypto.DecryptStandalone(data, passphrase)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("decryption failed: %v", err)
		return result
	}
	defer crypto.ZeroBytes(decryptedData)

	// Extract key JSON from backup payload (may be a bundle with embedded template)
	keyJSON, templateYAML, templateType, err := ParseBackup(decryptedData)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to parse backup payload: %v", err)
		return result
	}

	keyMeta, err := keys.ParseKeyPayloadMetadata(keyJSON)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("invalid key format: %v", err)
		return result
	}
	if _, err := keys.ValidateCurrentKeyPayload(keyJSON); err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}

	// Validate required fields
	if keyMeta.KeyType == "" {
		result.Valid = false
		result.Error = "missing key type"
		return result
	}
	if err := validateBackupKeyType(keyMeta.KeyType); err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}
	if err := verifyBundledTemplate(templateYAML, templateType, keyMeta.KeyType); err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}

	if keyMeta.BytecodeHex != "" {
		bytecode, err := keys.DecodeKeyPayloadBytecode(keyJSON)
		if err != nil {
			result.Valid = false
			result.Error = err.Error()
			return result
		}
		if _, err := keys.ValidateLogicSigSaltedBytecode(keyJSON, bytecode); err != nil {
			result.Valid = false
			result.Error = err.Error()
			return result
		}
		if opts.ValidateBundledTemplateBytecode && len(templateYAML) > 0 {
			if err := verifyBundledTemplateMatchesKey(keyJSON, templateYAML, templateType, bytecode, address, opts); err != nil {
				result.Valid = false
				result.Error = err.Error()
				return result
			}
		}
		derivedAddress, err := logicSigAddress(bytecode)
		if err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("failed to derive LogicSig address: %v", err)
			return result
		}
		if keyMeta.Category == keys.CategoryGenericLsig && keyMeta.Address != "" && keyMeta.Address != derivedAddress {
			result.Valid = false
			result.Error = fmt.Sprintf("address mismatch: stored=%s, derived=%s", keyMeta.Address, derivedAddress)
			return result
		}
		if derivedAddress != address {
			result.Valid = false
			result.Error = fmt.Sprintf("address mismatch: filename=%s, derived=%s", address, derivedAddress)
			return result
		}

		result.Valid = true
		result.KeyType = keyMeta.KeyType
		return result
	}

	if keyMeta.PublicKeyHex == "" || keyMeta.PrivateKeyHex == "" {
		result.Valid = false
		result.Error = "missing key data"
		return result
	}

	if keyMeta.Category == keys.CategoryComponent {
		publicKey, err := hex.DecodeString(keyMeta.PublicKeyHex)
		if err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("failed to decode sentry public key: %v", err)
			return result
		}
		componentKey, err := keytypes.ComponentKeySelector(keyMeta.KeyType, publicKey)
		if err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("failed to derive Sentry Key ID: %v", err)
			return result
		}
		if componentKey != address {
			result.Valid = false
			result.Error = fmt.Sprintf("Sentry Key ID mismatch: filename=%s, derived=%s", address, componentKey)
			return result
		}
		result.Valid = true
		result.KeyType = keyMeta.KeyType
		return result
	}

	// Verify address matches filename (derive from public key)
	deriver, err := addressderive.Get(keyMeta.KeyType)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("unsupported key type: %s", keyMeta.KeyType)
		return result
	}

	derivedAddress, err := deriver.DeriveAddress(keyMeta.PublicKeyHex, keyMeta.Parameters)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("failed to derive address: %v", err)
		return result
	}

	if derivedAddress != address {
		result.Valid = false
		result.Error = fmt.Sprintf("address mismatch: filename=%s, derived=%s", address, derivedAddress)
		return result
	}

	result.Valid = true
	result.KeyType = keyMeta.KeyType
	return result
}

func logicSigAddress(bytecode []byte) (string, error) {
	lsig := sdkcrypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	addr, err := lsig.Address()
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func verifyBundledTemplate(templateYAML []byte, templateType, keyType string) error {
	if err := validateBackupKeyType(keyType); err != nil {
		return err
	}

	if len(templateYAML) == 0 {
		if templateType != "" {
			return fmt.Errorf("backup bundle has template_type %q without template_yaml", templateType)
		}
		return nil
	}
	var tt templatestore.TemplateType
	switch templateType {
	case string(templatestore.TemplateTypeGeneric):
		tt = templatestore.TemplateTypeGeneric
	case string(templatestore.TemplateTypeComposed):
		tt = templatestore.TemplateTypeComposed
	default:
		return fmt.Errorf("backup bundle has unsupported template_type %q", templateType)
	}
	parsed, err := templatelibrary.ParseYAMLAs("", templateYAML, tt)
	if err != nil {
		return fmt.Errorf("invalid bundled template: %w", err)
	}
	if err := validateBackupKeyType(parsed.KeyType); err != nil {
		return err
	}
	if parsed.KeyType != keyType {
		return fmt.Errorf("backup bundle template key type %s does not match key type %s", parsed.KeyType, keyType)
	}
	return nil
}

func verifyBundledTemplateMatchesKey(
	keyJSON []byte,
	templateYAML []byte,
	templateType string,
	storedBytecode []byte,
	fileAddress string,
	opts DeepVerifyOptions,
) error {
	if opts.AlgodClient == nil {
		return fmt.Errorf("bundled template validation requires algod client")
	}

	keyMeta, err := keys.ParseKeyPayloadMetadata(keyJSON)
	if err != nil {
		return fmt.Errorf("invalid key format: %w", err)
	}
	params := keyMeta.Parameters
	if params == nil {
		params = map[string]string{}
	}

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	var compiledBytecode []byte
	var compiledAddress string
	switch templateType {
	case string(templatestore.TemplateTypeGeneric):
		compiledBytecode, compiledAddress, err = compileBundledGenericTemplate(ctx, templateYAML, params, opts.AlgodClient)
	case string(templatestore.TemplateTypeComposed):
		compiledBytecode, compiledAddress, err = compileBundledComposedTemplate(ctx, templateYAML, keyMeta.PublicKeyHex, params, opts.AlgodClient)
	default:
		return fmt.Errorf("backup bundle has unsupported template_type %q", templateType)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(compiledBytecode, storedBytecode) {
		return fmt.Errorf("bundled template does not reproduce key bytecode for %s", keyMeta.KeyType)
	}

	derivedAddress, err := logicSigAddress(compiledBytecode)
	if err != nil {
		return fmt.Errorf("failed to derive bundled template LogicSig address: %w", err)
	}
	if compiledAddress != "" && compiledAddress != derivedAddress {
		return fmt.Errorf("bundled template compiled address mismatch: algod=%s, derived=%s", compiledAddress, derivedAddress)
	}
	if fileAddress != "" && derivedAddress != fileAddress {
		return fmt.Errorf("bundled template address mismatch: filename=%s, derived=%s", fileAddress, derivedAddress)
	}
	return nil
}

func compileBundledGenericTemplate(ctx context.Context, templateYAML []byte, params map[string]string, client *algod.Client) ([]byte, string, error) {
	spec, err := generictemplate.ParseTemplateSpec(templateYAML)
	if err != nil {
		return nil, "", fmt.Errorf("invalid bundled generic template: %w", err)
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		return nil, "", fmt.Errorf("invalid bundled generic template: %w", err)
	}
	template := generictemplate.NewYAMLTemplate(spec)
	bytecode, address, err := template.Compile(ctx, params, client)
	if err != nil {
		return nil, "", fmt.Errorf("failed to compile bundled generic template: %w", err)
	}
	return bytecode, address, nil
}

func compileBundledComposedTemplate(ctx context.Context, templateYAML []byte, publicKeyHex string, params map[string]string, client *algod.Client) ([]byte, string, error) {
	spec, err := composeddsa.ParseTemplateSpec(templateYAML)
	if err != nil {
		return nil, "", fmt.Errorf("invalid bundled composed template: %w", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		return nil, "", fmt.Errorf("invalid bundled composed template: %w", err)
	}
	if publicKeyHex == "" {
		return nil, "", fmt.Errorf("bundled composed template validation requires public_key")
	}
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, "", fmt.Errorf("invalid public_key: %w", err)
	}
	provider.SetAlgodClient(client)
	bytecode, address, err := provider.DeriveLsig(ctx, publicKey, params)
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive bundled composed template LogicSig: %w", err)
	}
	return bytecode, address, nil
}
