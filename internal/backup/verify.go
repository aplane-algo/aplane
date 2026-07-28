// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
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
	// TemplateProvenanceUnavailable records that the bundled template could
	// not be recompiled because the TEAL compiler was unreachable. The key
	// itself validated; only the template-to-key correspondence is unproven.
	TemplateProvenanceUnavailable bool
	// TemplateProvenanceNote explains why the check could not run.
	TemplateProvenanceNote string
}

// VerifyReport contains the results of verifying a backup directory
type VerifyReport struct {
	BackupDir   string
	TotalFiles  int
	ValidFiles  int
	FailedFiles int
	// ProvenanceUnavailableFiles counts valid keys whose bundled template
	// could not be checked because the compiler was unreachable.
	ProvenanceUnavailableFiles int
	Results                    []VerifyResult
}

// ErrTemplateProvenanceUnavailable marks a bundled-template check that could
// not run because the TEAL compiler was unreachable. It is strictly absence of
// evidence: a template that compiles and does not match the key's bytecode
// fails with an ordinary error and is never reported this way.
var ErrTemplateProvenanceUnavailable = errors.New("bundled template provenance could not be verified")

// DeepVerifyOptions controls optional backup checks that require external
// services or stricter archive semantics than regular restore needs.
type DeepVerifyOptions struct {
	// ValidateBundledTemplateBytecode recompiles any bundled LogicSig template
	// and verifies that it reproduces the key's stored LogicSig bytecode.
	ValidateBundledTemplateBytecode bool
	AlgodClient                     *algod.Client
	Context                         context.Context
}

// DeepVerifyBackup performs deep validation by decrypting and validating all key files.
// backupDir is the backup root (containing keys/ subdirectory).
// Requires the export passphrase used to create the standalone backup.
func DeepVerifyBackup(backupDir, passphrase string) (*VerifyReport, error) {
	return DeepVerifyBackupBytes(backupDir, []byte(passphrase), DeepVerifyOptions{})
}

// DeepVerifyBackupWithOptions performs deep validation by decrypting and validating
// all key files, with optional template-to-key bytecode validation.
func DeepVerifyBackupWithOptions(backupDir, passphrase string, opts DeepVerifyOptions) (*VerifyReport, error) {
	return DeepVerifyBackupBytes(backupDir, []byte(passphrase), opts)
}

// DeepVerifyBackupBytes is the []byte passphrase entry point. Callers that
// hold the passphrase as zeroable bytes should use this so no immutable
// string copy of the secret is ever created.
func DeepVerifyBackupBytes(backupDir string, passphrase []byte, opts DeepVerifyOptions) (*VerifyReport, error) {
	// The sealed manifest authenticates the archive as a whole before any
	// member is trusted: a removed, added, or altered member fails here,
	// which per-payload authentication cannot detect on its own.
	if _, err := OpenSealedManifest(backupDir, passphrase); err != nil {
		return nil, err
	}

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
		result := verifyFileDeep(keysDir, address, passphrase, opts)
		report.Results = append(report.Results, result)

		if result.Valid {
			report.ValidFiles++
		} else {
			report.FailedFiles++
		}
		if result.TemplateProvenanceUnavailable {
			report.ProvenanceUnavailableFiles++
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

	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("invalid key format: %v", err)
		return result
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}

	if err := validateBackupKeyType(payload.KeyType); err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}
	if err := verifyBundledTemplate(templateYAML, templateType, payload.KeyType); err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}

	if len(payload.LogicSigBytecode) > 0 && opts.ValidateBundledTemplateBytecode && len(templateYAML) > 0 {
		if err := verifyBundledTemplateMatchesKey(payload, templateYAML, templateType, payload.LogicSigBytecode, address, opts); errors.Is(err, ErrTemplateProvenanceUnavailable) {
			// The key validated; only the template-to-key correspondence is
			// unproven. Report it so the caller can decide, rather than
			// failing a key whose own authority is intact.
			result.TemplateProvenanceUnavailable = true
			result.TemplateProvenanceNote = err.Error()
		} else if err != nil {
			result.Valid = false
			result.Error = err.Error()
			return result
		}
	}

	// Selector() is the single address authority for every category (for lsig
	// payloads it IS the bytecode-derived address), so the filename comparison
	// below is the complete tamper check.
	if selector != address {
		result.Valid = false
		result.Error = fmt.Sprintf("address mismatch: filename=%s, derived=%s", address, selector)
		return result
	}

	result.Valid = true
	result.KeyType = payload.KeyType
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
	payload *keys.Payload,
	templateYAML []byte,
	templateType string,
	storedBytecode []byte,
	fileAddress string,
	opts DeepVerifyOptions,
) error {
	if opts.AlgodClient == nil {
		return fmt.Errorf("%w: no TEAL compiler client is configured", ErrTemplateProvenanceUnavailable)
	}
	params := payload.Parameters
	if params == nil {
		params = map[string]string{}
	}

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	var compiledBytecode []byte
	var compiledAddress string
	var err error
	switch templateType {
	case string(templatestore.TemplateTypeGeneric):
		compiledBytecode, compiledAddress, err = compileBundledGenericTemplate(ctx, templateYAML, params, opts.AlgodClient)
	case string(templatestore.TemplateTypeComposed):
		compiledBytecode, compiledAddress, err = compileBundledComposedTemplate(ctx, templateYAML, hex.EncodeToString(payload.PublicKey), params, opts.AlgodClient)
	default:
		return fmt.Errorf("backup bundle has unsupported template_type %q", templateType)
	}
	if err != nil {
		// The compiler could not answer. That is absence of evidence, not
		// evidence of a bad template, and callers may treat it differently
		// from a template that compiles into the wrong bytecode below.
		return fmt.Errorf("%w: %v", ErrTemplateProvenanceUnavailable, err)
	}
	if !bytes.Equal(compiledBytecode, storedBytecode) {
		return fmt.Errorf("bundled template does not reproduce key bytecode for %s", payload.KeyType)
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
