// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/merklewhitelist"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// ErrMissingLogicSigSaltCounter indicates a LogicSig key file predates the
// off-curve address invariant and cannot be safely loaded.
var ErrMissingLogicSigSaltCounter = errors.New("logic sig key file missing salt_counter")

// ErrIncompatibleKeyFormat indicates a key payload belongs to a state that this
// runtime no longer loads directly.
var ErrIncompatibleKeyFormat = errors.New("incompatible key file format")

// ErrAddressCollision indicates multiple key files resolve to the same signing
// address. The keyset is ambiguous and must not publish a runtime key snapshot.
var ErrAddressCollision = errors.New("address collision")

// AddressCollisionError reports one or more duplicate signing addresses found
// during key scan.
type AddressCollisionError struct {
	Collisions map[string][]string
}

func (e *AddressCollisionError) Error() string {
	if e == nil || len(e.Collisions) == 0 {
		return ErrAddressCollision.Error()
	}
	addresses := make([]string, 0, len(e.Collisions))
	for address := range e.Collisions {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)

	parts := make([]string, 0, len(addresses))
	for _, address := range addresses {
		files := append([]string(nil), e.Collisions[address]...)
		sort.Strings(files)
		parts = append(parts, fmt.Sprintf("%s: %s", address, strings.Join(files, ", ")))
	}
	return fmt.Sprintf("%v: multiple key files resolve to the same signing address (%s)", ErrAddressCollision, strings.Join(parts, "; "))
}

func (e *AddressCollisionError) Unwrap() error {
	return ErrAddressCollision
}

func newAddressCollisionError(addressFiles map[string][]string) *AddressCollisionError {
	collisions := make(map[string][]string)
	for address, files := range addressFiles {
		if len(files) < 2 {
			continue
		}
		collisions[address] = append([]string(nil), files...)
		sort.Strings(collisions[address])
	}
	if len(collisions) == 0 {
		return nil
	}
	return &AddressCollisionError{Collisions: collisions}
}

func keyPayloadScanWarningCode(err error) KeyScanWarningCode {
	if errors.Is(err, ErrMissingLogicSigSaltCounter) {
		return KeyScanWarningLogicSigSaltInvalid
	}
	reason := strings.ToLower(err.Error())
	if strings.Contains(reason, "on-curve") {
		return KeyScanWarningLogicSigAddressInvalid
	}
	if strings.Contains(reason, "lsig_bytecode") || strings.Contains(reason, "logic sig") {
		return KeyScanWarningParseLogicSigFailed
	}
	if errors.Is(err, ErrIncompatibleKeyFormat) {
		return KeyScanWarningIncompatibleFormat
	}
	return KeyScanWarningDetectKeyTypeFailed
}

// KeyPayloadHeader is the non-secret schema header required on current key files.
type KeyPayloadHeader struct {
	FormatVersion int
	Category      string
	KeyType       string
}

// ValidateCurrentKeyPayload verifies that decrypted key JSON uses the current
// canonical schema. It does not validate cryptographic material; callers still
// perform key-type-specific checks after this header check.
func ValidateCurrentKeyPayload(data []byte) (KeyPayloadHeader, error) {
	meta, err := ParseKeyPayloadMetadata(data)
	if err != nil {
		return KeyPayloadHeader{}, err
	}
	return validateCurrentKeyPayloadMetadata(meta)
}

func validateCurrentKeyPayloadMetadata(meta KeyPayloadMetadata) (KeyPayloadHeader, error) {
	if !meta.HasFormatVersion {
		return KeyPayloadHeader{}, incompatibleKeyFormat("missing format_version")
	}
	if meta.FormatVersion != CurrentKeyFormatVersion {
		return KeyPayloadHeader{}, incompatibleKeyFormat("format_version %d is not supported by this runtime; expected %d", meta.FormatVersion, CurrentKeyFormatVersion)
	}
	if strings.TrimSpace(meta.Category) == "" {
		return KeyPayloadHeader{}, incompatibleKeyFormat("missing category")
	}
	switch meta.Category {
	case CategoryEd25519, CategoryDSALsig, CategoryGenericLsig, CategoryComponent:
	default:
		return KeyPayloadHeader{}, incompatibleKeyFormat("unknown category %q", meta.Category)
	}
	if strings.TrimSpace(meta.KeyType) == "" {
		return KeyPayloadHeader{}, incompatibleKeyFormat("missing key_type")
	}
	if meta.Category == CategoryComponent && !keytypes.IsSentryComponentKeyType(meta.KeyType) {
		return KeyPayloadHeader{}, incompatibleKeyFormat("component category requires a sentry key type, got %q", meta.KeyType)
	}
	if meta.HasRuntimeArgs {
		return KeyPayloadHeader{}, incompatibleKeyFormat("legacy runtime_args field; use signing_args")
	}
	return KeyPayloadHeader{
		FormatVersion: meta.FormatVersion,
		Category:      meta.Category,
		KeyType:       meta.KeyType,
	}, nil
}

func incompatibleKeyFormat(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s; restore or regenerate the key file using the current key schema", ErrIncompatibleKeyFormat, fmt.Sprintf(format, args...))
}

// KeyScanInfo holds information about a scanned key file.
// This allows scanning to extract all needed info in a single decrypt operation,
// avoiding the need to re-decrypt keys for /keys API or signing budget calculation.
type KeyScanInfo struct {
	KeyFile                string // Path to the key file
	KeyType                string // Key type (ed25519, aplane.falcon1024.v1, timelock-v3, etc.)
	Category               string // Key category from the key file, if present
	LsigSize               int    // Total LogicSig size in bytes (bytecode + signature), 0 for ed25519
	PublicKeyHex           string // Hex-encoded public key (for /keys API)
	BaseKeyType            string // Base DSA key type used for signing metadata, if present
	Parameters             map[string]string
	SigningArgs            []StoredSigningArg
	SigningMetadataVersion int
	TemplateFingerprint    string
	CreatedAt              string // RFC 3339 creation timestamp (empty for legacy keys)
}

// KeyScanWarningCode classifies a key file skipped during directory scan.
type KeyScanWarningCode string

const (
	KeyScanWarningReadFailed              KeyScanWarningCode = "read_failed"
	KeyScanWarningDetectKeyTypeFailed     KeyScanWarningCode = "detect_key_type_failed"
	KeyScanWarningIncompatibleFormat      KeyScanWarningCode = "incompatible_key_format"
	KeyScanWarningParseLogicSigFailed     KeyScanWarningCode = "parse_logic_sig_failed"
	KeyScanWarningLogicSigSaltInvalid     KeyScanWarningCode = "logic_sig_salt_invalid"
	KeyScanWarningLogicSigAddressInvalid  KeyScanWarningCode = "logic_sig_address_invalid"
	KeyScanWarningAddressDerivationFailed KeyScanWarningCode = "address_derivation_failed"
	KeyScanWarningFilenameAddressMismatch KeyScanWarningCode = "filename_address_mismatch"
)

// KeyScanWarning describes a recoverable key-scan failure. Scanning continues
// after these failures, but the affected key file is not loaded.
type KeyScanWarning struct {
	Code    KeyScanWarningCode
	KeyFile string
	Err     error
}

func (w KeyScanWarning) Error() string {
	return w.Message()
}

func (w KeyScanWarning) Reason() string {
	if w.Err != nil {
		return w.Err.Error()
	}
	return string(w.Code)
}

func (w KeyScanWarning) Message() string {
	switch w.Code {
	case KeyScanWarningReadFailed:
		return fmt.Sprintf("Failed to read key file %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningDetectKeyTypeFailed:
		return fmt.Sprintf("Failed to detect key type for %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningIncompatibleFormat:
		return fmt.Sprintf("Skipped incompatible key file %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningParseLogicSigFailed:
		return fmt.Sprintf("Failed to parse lsig file %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningLogicSigSaltInvalid:
		return fmt.Sprintf("Failed to validate LogicSig salt metadata for %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningLogicSigAddressInvalid:
		return fmt.Sprintf("Failed to derive address from bytecode for %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningAddressDerivationFailed:
		return fmt.Sprintf("Failed to derive address for %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningFilenameAddressMismatch:
		return fmt.Sprintf("Skipped key file %s: %v", w.KeyFile, w.Err)
	default:
		return fmt.Sprintf("Failed to scan key file %s: %v", w.KeyFile, w.Err)
	}
}

// IsLogicSigSaltMetadata reports whether this warning means a persisted
// LogicSig key was rejected by the off-curve salt invariant.
func (w KeyScanWarning) IsLogicSigSaltMetadata() bool {
	return w.Code == KeyScanWarningLogicSigSaltInvalid
}

// KeyScanReport carries loaded keys plus recoverable warnings for skipped files.
type KeyScanReport struct {
	Keys     map[string]KeyScanInfo
	Warnings []KeyScanWarning
}

// KeyScanWarningProvider exposes recoverable warnings from the most recent key
// scan. Signer application code uses this to audit security-relevant key
// rejections without coupling key scanning to signer audit packages.
type KeyScanWarningProvider interface {
	GetScanWarnings() []KeyScanWarning
}

// ReadAndDecryptFile reads a file and decrypts it with the master key.
// Runtime key files must be encrypted; plaintext key payloads belong in
// explicit import or migration paths, not normal signing paths.
func ReadAndDecryptFile(path string, masterKey []byte, entityName string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", entityName, err)
	}

	if !crypto.IsEncrypted(data) {
		return nil, fmt.Errorf("%s must be encrypted", entityName)
	}

	if len(masterKey) == 0 {
		return nil, fmt.Errorf("%s is encrypted but no master key provided", entityName)
	}

	decrypted, err := crypto.DecryptWithMasterKey(data, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt %s with master key: %w", entityName, err)
	}
	return decrypted, nil
}

// ReadDecryptedKeyJSONWithMasterKey reads a key file and decrypts with the master key.
func ReadDecryptedKeyJSONWithMasterKey(keyFile string, masterKey []byte) ([]byte, error) {
	return ReadAndDecryptFile(keyFile, masterKey, "key file")
}

// ScanKeysDirectoryWithMasterKey scans the identity-scoped keys subdirectory using a master key for decryption.
// Only supports envelope_version 2 files.
func ScanKeysDirectoryWithMasterKey(paths storepaths.Paths, identityID string, masterKey []byte) (map[string]KeyScanInfo, error) {
	report, err := ScanKeysDirectoryWithMasterKeyReport(paths, identityID, masterKey)
	if err != nil {
		return nil, err
	}
	return report.Keys, nil
}

// ScanKeysDirectoryWithMasterKeyReport scans the identity-scoped keys
// subdirectory and returns structured warnings for key files that were skipped.
func ScanKeysDirectoryWithMasterKeyReport(paths storepaths.Paths, identityID string, masterKey []byte) (*KeyScanReport, error) {
	return scanKeysDirectoryInternalReport(paths, identityID, func(keyFile string) ([]byte, error) {
		return ReadDecryptedKeyJSONWithMasterKey(keyFile, masterKey)
	})
}

// scanKeysDirectoryInternalReport is the shared implementation for scanning
// keys. The decryptFunc parameter allows using either passphrase or master key
// decryption.
func scanKeysDirectoryInternalReport(paths storepaths.Paths, identityID string, decryptFunc func(keyFile string) ([]byte, error)) (*KeyScanReport, error) {
	keysMap := make(map[string]KeyScanInfo)
	addressFiles := make(map[string][]string)
	var warnings []KeyScanWarning
	warn := func(code KeyScanWarningCode, keyFile string, err error) {
		warning := KeyScanWarning{Code: code, KeyFile: keyFile, Err: err}
		warnings = append(warnings, warning)
		// Stderr, not stdout: callers emit machine-readable output on stdout
		// and surface report.Warnings through their own channels.
		_, _ = fmt.Fprintf(os.Stderr, "Warning: %s\n", warning.Message())
	}

	keysDir := paths.KeysDir(identityID)

	// Ensure keys directory exists
	if err := fsutil.MkdirAll(keysDir); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Read keys directory
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys directory: %w", err)
	}

	// Scan for .key files (all key types: Ed25519, Falcon-1024, LogicSigs)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}

		filenameAddress := strings.TrimSuffix(entry.Name(), ".key")
		keyFile := paths.KeyFilePath(identityID, filenameAddress)

		// Read and decrypt the file ONCE to extract all needed info
		data, err := decryptFunc(keyFile)
		if err != nil {
			warn(KeyScanWarningReadFailed, keyFile, err)
			continue
		}

		payload, err := ParsePayload(data)
		if err != nil {
			crypto.ZeroBytes(data)
			warn(keyPayloadScanWarningCode(err), keyFile, err)
			continue
		}
		address, err := payload.Selector()
		if err != nil {
			payload.ZeroSecrets()
			crypto.ZeroBytes(data)
			warn(KeyScanWarningAddressDerivationFailed, keyFile, err)
			continue
		}
		payloadMeta := payload.Metadata()
		signingMeta := SigningMetadata{
			Category:               payloadMeta.Category,
			BaseKeyType:            payloadMeta.BaseKeyType,
			Parameters:             maps.Clone(payloadMeta.Parameters),
			SigningArgs:            payloadMeta.SigningArgs,
			SigningMetadataVersion: payloadMeta.SigningMetadataVersion,
		}
		keyType := payloadMeta.KeyType
		category := payloadMeta.Category
		publicKeyHex := payloadMeta.PublicKeyHex
		var lsigSize int
		switch category {
		case CategoryGenericLsig:
			publicKeyHex = ""
			lsigSize = len(payload.LogicSigBytecode)
		case CategoryDSALsig:
			lsigSize = len(payload.LogicSigBytecode) + dsaLogicSigArgBudgetForKey(keyType, signingMeta.BaseKeyType)
		}

		createdAt := payloadMeta.CreatedAt
		payload.ZeroSecrets()
		crypto.ZeroBytes(data) // Zero after all processing complete
		if filenameAddress != address {
			warn(KeyScanWarningFilenameAddressMismatch, keyFile, fmt.Errorf("filename address %s does not match payload-derived address %s", filenameAddress, address))
			continue
		}

		addressFiles[address] = append(addressFiles[address], keyFile)
		if len(addressFiles[address]) > 1 {
			delete(keysMap, address)
			continue
		}

		keysMap[address] = KeyScanInfo{
			KeyFile:                keyFile,
			KeyType:                keyType,
			Category:               category,
			LsigSize:               lsigSize,
			PublicKeyHex:           publicKeyHex,
			BaseKeyType:            signingMeta.BaseKeyType,
			Parameters:             signingMeta.Parameters,
			SigningArgs:            signingMeta.SigningArgs,
			SigningMetadataVersion: signingMeta.SigningMetadataVersion,
			TemplateFingerprint:    payloadMeta.TemplateFingerprint,
			CreatedAt:              createdAt,
		}
	}

	if err := newAddressCollisionError(addressFiles); err != nil {
		return nil, err
	}

	return &KeyScanReport{Keys: keysMap, Warnings: warnings}, nil
}

// IsComponentKey classifies a key payload as a sentry key.
func IsComponentKey(category string) bool {
	return category == CategoryComponent
}

// IsGenericKey classifies a key payload from durable key-file metadata.
// Current keys use category as authoritative; legacy keys without category
// fall back to the generic LogicSig provider registry.
func IsGenericKey(category, keyType string) bool {
	if category == CategoryGenericLsig {
		return true
	}
	if category != "" {
		return false
	}
	return IsGenericLSigType(keyType)
}

const falcon1024WhitelistV2KeyType = "aplane.falcon1024-whitelist.v2"

func dsaLogicSigArgBudgetForKey(keyType, baseKeyType string) int {
	return cryptoSignatureSizeForKey(keyType, baseKeyType) + signerGeneratedDSAArgSizeForKey(keyType)
}

func cryptoSignatureSizeForKey(keyType, baseKeyType string) int {
	if size := logicsigdsa.GetCryptoSignatureSize(keyType); size > 0 {
		return size
	}
	if baseKeyType != "" {
		return logicsigdsa.GetCryptoSignatureSize(baseKeyType)
	}
	return 0
}

func signerGeneratedDSAArgSizeForKey(keyType string) int {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case falcon1024WhitelistV2KeyType, keytypes.CorridorV1:
		return merklewhitelist.ProofSize
	default:
		return 0
	}
}

// ExtractBytecode extracts the LogicSig bytecode from key data.
// Returns nil if no bytecode is present (e.g., native Ed25519 keys).
func ExtractBytecode(data []byte) []byte {
	bytecode, err := extractBytecodeStrict(data)
	if err != nil {
		return nil
	}
	return bytecode
}

// DecodeKeyPayloadBytecode extracts and decodes normalized LogicSig bytecode
// from key payload data, returning alias conflicts and invalid hex as errors.
func DecodeKeyPayloadBytecode(data []byte) ([]byte, error) {
	return extractBytecodeStrict(data)
}

func extractBytecodeStrict(data []byte) ([]byte, error) {
	fields, err := parseKeyPayloadFields(data)
	if err != nil {
		return nil, err
	}
	bytecodeHex, err := normalizedBytecodeHexFields(fields)
	if err != nil {
		return nil, err
	}
	if bytecodeHex == "" {
		return nil, nil
	}

	bytecode, err := hex.DecodeString(bytecodeHex)
	if err != nil {
		return nil, fmt.Errorf("invalid LogicSig bytecode hex: %w", err)
	}
	return bytecode, nil
}

// ExtractSaltCounter extracts the stored LogicSig salt counter from a key file
// payload. The boolean reports whether the field was present; zero is a valid
// counter value and must not be treated as absent.
func ExtractSaltCounter(data []byte) (byte, bool) {
	var meta struct {
		SaltCounter *byte `json:"salt_counter"`
	}
	if err := json.Unmarshal(data, &meta); err != nil || meta.SaltCounter == nil {
		return 0, false
	}
	return *meta.SaltCounter, true
}

// RequireLogicSigSaltCounter enforces that a LogicSig key file contains the
// persisted salt counter required by the off-curve address invariant.
func RequireLogicSigSaltCounter(data []byte) (byte, error) {
	counter, ok := ExtractSaltCounter(data)
	if !ok {
		return 0, ErrMissingLogicSigSaltCounter
	}
	return counter, nil
}

// ValidateLogicSigSaltedBytecode enforces the persisted LogicSig off-curve
// invariant for key-file payloads that contain bytecode.
func ValidateLogicSigSaltedBytecode(data []byte, bytecode []byte) (byte, error) {
	if len(bytecode) == 0 {
		return 0, fmt.Errorf("logic sig key file missing or invalid bytecode")
	}
	counter, err := RequireLogicSigSaltCounter(data)
	if err != nil {
		return 0, err
	}
	addr, err := logicSigAddressBytes(bytecode)
	if err != nil {
		return 0, fmt.Errorf("failed to derive LogicSig address: %w", err)
	}
	if lsigsalt.IsOnCurve(addr) {
		return 0, fmt.Errorf("logic sig key file address is on-curve")
	}
	return counter, nil
}

// extractPublicKeyHex extracts the public key hex from key data.
func extractPublicKeyHex(data []byte) string {
	meta, err := ParseKeyPayloadMetadata(data)
	if err != nil {
		return ""
	}
	return meta.PublicKeyHex
}

// logicSigAddress computes the LogicSig address from bytecode.
func logicSigAddress(bytecode []byte) (string, error) {
	addr, err := logicSigAddressBytes(bytecode)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func logicSigAddressBytes(bytecode []byte) (types.Address, error) {
	lsig := sdkcrypto.LogicSigAccount{
		Lsig: types.LogicSig{Logic: bytecode},
	}
	return lsig.Address()
}

type SigningMetadata struct {
	Category               string
	BaseKeyType            string
	Parameters             map[string]string
	SigningArgs            []StoredSigningArg
	SigningMetadataVersion int
}

func ExtractSigningMetadata(data []byte) SigningMetadata {
	meta, err := ParseKeyPayloadMetadata(data)
	if err != nil {
		return SigningMetadata{}
	}
	return SigningMetadata{
		Category:               meta.Category,
		BaseKeyType:            meta.BaseKeyType,
		Parameters:             maps.Clone(meta.Parameters),
		SigningArgs:            meta.SigningArgs,
		SigningMetadataVersion: meta.SigningMetadataVersion,
	}
}

// extractCreatedAt extracts the created_at timestamp from key data.
// Returns empty string if not present (legacy keys).
func extractCreatedAt(data []byte) string {
	meta, err := ParseKeyPayloadMetadata(data)
	if err != nil {
		return ""
	}
	return meta.CreatedAt
}

func DetectKeyTypeFromData(data []byte) (string, error) {
	meta, err := ParseKeyPayloadMetadata(data)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal key type: %w", err)
	}

	if meta.KeyType != "" {
		return meta.KeyType, nil
	}

	return "", fmt.Errorf("key file missing required 'key_type' field")
}
