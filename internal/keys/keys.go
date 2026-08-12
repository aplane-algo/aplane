// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/storepaths"

	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// witnessArtifactBundleSuffix mirrors witness/artifact.BundleExtension.
// External witness artifact bundles are aprekey-owned and never valid signer
// store residents; the scan recognizes the suffix only to report them with a
// targeted message and must never decrypt them.
const witnessArtifactBundleSuffix = ".wit"

// ErrMissingLogicSigSaltCounter indicates a LogicSig key file predates the
// off-curve address invariant and cannot be safely loaded.
var ErrMissingLogicSigSaltCounter = errors.New("logic sig key file missing salt_counter")

// ErrLogicSigAddressOnCurve indicates a stored LogicSig key file whose bytecode
// derives an on-curve address, violating the off-curve salt invariant.
var ErrLogicSigAddressOnCurve = errors.New("logic sig key file address is on-curve")

// ErrInvalidLogicSigBytecode indicates a LogicSig key file whose stored
// bytecode is missing, undecodable, or cannot derive an address.
var ErrInvalidLogicSigBytecode = errors.New("logic sig key file bytecode is missing or invalid")

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
	switch {
	case errors.Is(err, ErrMissingLogicSigSaltCounter):
		return KeyScanWarningLogicSigSaltInvalid
	case errors.Is(err, ErrLogicSigAddressOnCurve):
		return KeyScanWarningLogicSigAddressInvalid
	case errors.Is(err, ErrInvalidLogicSigBytecode):
		return KeyScanWarningParseLogicSigFailed
	case errors.Is(err, ErrIncompatibleKeyFormat):
		return KeyScanWarningIncompatibleFormat
	default:
		return KeyScanWarningDetectKeyTypeFailed
	}
}

func incompatibleKeyFormat(format string, args ...interface{}) error {
	return incompatibleKeyFormatErr(fmt.Errorf(format, args...))
}

// incompatibleKeyFormatErr wraps a payload validation failure so callers can
// match both ErrIncompatibleKeyFormat and any classification sentinel inside
// detail (e.g. ErrLogicSigAddressOnCurve).
func incompatibleKeyFormatErr(detail error) error {
	return fmt.Errorf("%w: %w; restore or regenerate the key file using the current key schema", ErrIncompatibleKeyFormat, detail)
}

// KeyScanInfo holds information about a scanned key file.
// This allows scanning to extract all needed info in a single decrypt operation,
// avoiding the need to re-decrypt keys for /keys API or signing budget calculation.
type KeyScanInfo struct {
	KeyFile                string // Path to the key file
	KeyType                string // Key type (ed25519, aplane.falcon1024.v1, timelock-v3, etc.)
	Category               string // Key category from the key file, if present
	PQScheme               string
	PQAddressSalt          *byte
	LogicSigResources      *lsigresource.Profile
	PublicKeyHex           string // Hex-encoded public key (for /keys API)
	BaseKeyType            string // Base DSA key type used for signing metadata, if present
	Parameters             map[string]string
	SigningArgs            []StoredSigningArg
	BoundedAuthorization   *boundedmeta.Metadata
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
	KeyScanWarningFilenameClassMismatch   KeyScanWarningCode = "filename_class_mismatch"
	KeyScanWarningUnexpectedEntry         KeyScanWarningCode = "unexpected_entry"
	KeyScanWarningWitnessMetadataInvalid  KeyScanWarningCode = "witness_metadata_invalid"
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
	case KeyScanWarningFilenameClassMismatch:
		return fmt.Sprintf("Skipped managed credential %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningUnexpectedEntry:
		return fmt.Sprintf("Unexpected entry in keys namespace %s: %v", w.KeyFile, w.Err)
	case KeyScanWarningWitnessMetadataInvalid:
		return fmt.Sprintf("Invalid witness public metadata %s: %v", w.KeyFile, w.Err)
	default:
		return fmt.Sprintf("Failed to scan key file %s: %v", w.KeyFile, w.Err)
	}
}

// IsLogicSigInvariantViolation reports whether this warning means a persisted
// LogicSig key was rejected by a LogicSig integrity invariant: missing salt
// metadata, an on-curve address, or missing/undecodable bytecode. The signer
// audit-logs these rejections because they can indicate key-file tampering.
func (w KeyScanWarning) IsLogicSigInvariantViolation() bool {
	switch w.Code {
	case KeyScanWarningLogicSigSaltInvalid,
		KeyScanWarningLogicSigAddressInvalid,
		KeyScanWarningParseLogicSigFailed:
		return true
	default:
		return false
	}
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

// ReadAndDecryptFile reads a file and opens it under the current term as the
// object ctx names. Runtime key files must be encrypted; plaintext key
// payloads belong in explicit import or migration paths, not normal signing
// paths.
func ReadAndDecryptFile(path string, kr *crypto.Keyring, ctx crypto.ObjectContext, entityName string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", entityName, err)
	}

	if !crypto.IsEncrypted(data) {
		return nil, fmt.Errorf("%s must be encrypted", entityName)
	}

	if kr == nil {
		return nil, fmt.Errorf("%s is encrypted but the keystore is locked", entityName)
	}

	decrypted, err := kr.Open(data, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt %s: %w", entityName, err)
	}
	return decrypted, nil
}

// ReadDecryptedKeyJSONWithKeyring reads a managed credential and decrypts
// it as the object its canonical filename names.
func ReadDecryptedKeyJSONWithKeyring(keyFile string, kr *crypto.Keyring) ([]byte, error) {
	ctx, err := CredentialContextForFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ReadAndDecryptFile(keyFile, kr, ctx, "key file")
}

// ScanKeysDirectoryWithKeyring scans the identity-scoped keys subdirectory,
// opening each credential with the keyring. Only term envelopes are read.
func ScanKeysDirectoryWithKeyring(paths storepaths.Paths, identityID string, kr *crypto.Keyring) (map[string]KeyScanInfo, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return nil, err
	}
	return ScanKeysDirectoryWithKeyringActive(active, kr)
}

// ScanKeysDirectoryWithKeyringActive is ScanKeysDirectoryWithKeyring
// against resolved active-store paths (generational or legacy).
func ScanKeysDirectoryWithKeyringActive(active storepaths.ActivePaths, kr *crypto.Keyring) (map[string]KeyScanInfo, error) {
	report, err := ScanKeysDirectoryWithKeyringReportActive(active, kr)
	if err != nil {
		return nil, err
	}
	return report.Keys, nil
}

// ScanKeysDirectoryWithKeyringReport scans the identity-scoped keys
// subdirectory and returns structured warnings for key files that were skipped.
func ScanKeysDirectoryWithKeyringReport(paths storepaths.Paths, identityID string, kr *crypto.Keyring) (*KeyScanReport, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return nil, err
	}
	return ScanKeysDirectoryWithKeyringReportActive(active, kr)
}

// ScanKeysDirectoryWithKeyringReportActive is
// ScanKeysDirectoryWithKeyringReport against resolved active-store paths.
func ScanKeysDirectoryWithKeyringReportActive(active storepaths.ActivePaths, kr *crypto.Keyring) (*KeyScanReport, error) {
	return scanKeysDirectoryInternalReport(active, func(keyFile string) ([]byte, error) {
		return ReadDecryptedKeyJSONWithKeyring(keyFile, kr)
	})
}

// scanKeysDirectoryInternalReport is the shared implementation for scanning
// keys. The decryptFunc parameter lets the caller supply either passphrase or
// keyring decryption.
func scanKeysDirectoryInternalReport(active storepaths.ActivePaths, decryptFunc func(keyFile string) ([]byte, error)) (*KeyScanReport, error) {
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

	keysDir := active.KeysDir()

	// Ensure keys directory exists
	if err := fsutil.MkdirAllPrivate(keysDir); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Read keys directory
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys directory: %w", err)
	}

	// Scan only signer-managed private credential classes. Public witness
	// references (.wit.json) are the sole expected non-credential residents
	// and are validated without decryption; external witness artifact
	// bundles (.wit) are aprekey-owned and never signer store residents
	// (docs/ARCH_CONTRACTS.md). Everything unrecognized is reported so
	// generation-based stores can fail closed on unexpected content
	// (legacy stores keep tolerating it as a warning). Nothing outside the
	// managed credential classes ever reaches decryptFunc.
	for _, entry := range entries {
		filenameSelector, _, ok := ParseManagedCredentialFilename(entry.Name())
		if entry.IsDir() || !ok {
			entryPath := filepath.Join(keysDir, entry.Name())
			switch {
			case entry.IsDir():
				warn(KeyScanWarningUnexpectedEntry, entryPath,
					fmt.Errorf("not a managed credential"))
			case strings.HasSuffix(entry.Name(), WitnessPublicMetadataSuffix):
				if err := validateWitnessPublicMetadataFilename(entryPath); err != nil {
					warn(KeyScanWarningWitnessMetadataInvalid, entryPath, err)
				}
			case strings.HasSuffix(entry.Name(), witnessArtifactBundleSuffix):
				warn(KeyScanWarningUnexpectedEntry, entryPath,
					fmt.Errorf("external witness artifact bundles are aprekey-owned and not signer store residents; move it outside the keystore"))
			default:
				warn(KeyScanWarningUnexpectedEntry, entryPath,
					fmt.Errorf("not a managed credential"))
			}
			continue
		}

		keyFile := filepath.Join(keysDir, entry.Name())

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
		selector, err := payload.Selector()
		if err != nil {
			payload.ZeroSecrets()
			crypto.ZeroBytes(data)
			warn(KeyScanWarningAddressDerivationFailed, keyFile, err)
			continue
		}
		payloadMeta := payload.Metadata()
		signingMeta := payload.SigningMetadata()
		keyType := payloadMeta.KeyType
		category := payloadMeta.Category
		publicKeyHex := payloadMeta.PublicKeyHex
		if err := ValidateManagedCredentialFilename(entry.Name(), selector, category); err != nil {
			payload.ZeroSecrets()
			crypto.ZeroBytes(data)
			if errors.Is(err, ErrManagedCredentialClassMismatch) {
				warn(KeyScanWarningFilenameClassMismatch, keyFile, managedCredentialClassMismatchError(err))
			} else {
				warn(
					KeyScanWarningFilenameAddressMismatch,
					keyFile,
					fmt.Errorf("filename address %s does not match payload-derived address %s: %w", filenameSelector, selector, err),
				)
			}
			continue
		}
		var baseArgumentBytes int
		switch category {
		case CategoryGenericLsig:
			publicKeyHex = ""
		case CategoryDSALsig:
			if signingMeta.BoundedAuthorization == nil {
				baseArgumentBytes = dsaLogicSigArgBudgetForKey(keyType, signingMeta.BaseKeyType)
			}
		}
		logicSigResources, resourceErr := scanLogicSigResources(payload, baseArgumentBytes)
		if resourceErr != nil {
			payload.ZeroSecrets()
			crypto.ZeroBytes(data)
			warn(KeyScanWarningIncompatibleFormat, keyFile, resourceErr)
			continue
		}

		createdAt := payloadMeta.CreatedAt
		payload.ZeroSecrets()
		crypto.ZeroBytes(data) // Zero after all processing complete
		addressFiles[selector] = append(addressFiles[selector], keyFile)
		if len(addressFiles[selector]) > 1 {
			delete(keysMap, selector)
			continue
		}

		keysMap[selector] = KeyScanInfo{
			KeyFile:                keyFile,
			KeyType:                keyType,
			Category:               category,
			PQScheme:               signingMeta.PQScheme,
			PQAddressSalt:          cloneBytePtr(signingMeta.PQAddressSalt),
			LogicSigResources:      logicSigResources,
			PublicKeyHex:           publicKeyHex,
			BaseKeyType:            signingMeta.BaseKeyType,
			Parameters:             signingMeta.Parameters,
			SigningArgs:            signingMeta.SigningArgs,
			BoundedAuthorization:   boundedmeta.Clone(signingMeta.BoundedAuthorization),
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

func scanLogicSigResources(payload *Payload, baseArgumentBytes int) (*lsigresource.Profile, error) {
	if payload == nil || (payload.Category != CategoryDSALsig && payload.Category != CategoryGenericLsig) {
		return nil, nil
	}
	programBytes := len(payload.LogicSigBytecode)
	if programBytes == 0 {
		return nil, fmt.Errorf("LogicSig resource profile has empty program")
	}
	// Every supported LogicSig generation/import path attaches an opcode
	// profile before persistence, so a zero profile is a malformed or obsolete
	// development key file. Failing here beats materializing a profile with a
	// zero opcode ceiling that Profile.UsageForPath rejects later while signing.
	if payload.LogicSigOpcodeProfile == (lsigresource.OpcodeProfile{}) {
		return nil, fmt.Errorf("LogicSig resource profile has no opcode profile")
	}
	if metadata := payload.BoundedAuthorization; metadata != nil {
		return profileFromBoundedMetadata(uint64(programBytes), metadata, payload.LogicSigOpcodeProfile)
	}
	argumentBytes := baseArgumentBytes
	for _, arg := range payload.SigningArgs {
		if arg.ByteLength > 0 {
			argumentBytes += arg.ByteLength
		} else {
			argumentBytes += arg.MaxSize
		}
	}
	if argumentBytes < 0 {
		return nil, fmt.Errorf("LogicSig resource profile has negative argument size")
	}
	argumentBytesValue := uint64(argumentBytes)
	profile, err := lsigresource.Materialize(uint64(programBytes), &argumentBytesValue, nil, payload.LogicSigOpcodeProfile)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func profileFromBoundedMetadata(programBytes uint64, metadata *boundedmeta.Metadata, opcodes lsigresource.OpcodeProfile) (*lsigresource.Profile, error) {
	arguments := map[lsigresource.AuthorizationPath]uint64{
		lsigresource.PathSpend:         uint64(metadata.ArgumentBytesForPath(boundedmeta.PathSpend)),
		lsigresource.PathSpendingRekey: uint64(metadata.ArgumentBytesForPath(boundedmeta.PathSpendingRekey)),
		lsigresource.PathAdminRekey:    uint64(metadata.ArgumentBytesForPath(boundedmeta.PathAdminRekey)),
	}
	profile, err := lsigresource.Materialize(programBytes, nil, arguments, opcodes)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func managedCredentialClassMismatchError(err error) error {
	return fmt.Errorf(
		"%w. Stop apsigner before remediation: preserve the rejected file; if no verified .apb backup exists, use the prior build to export one; verify the backup; remove the stale managed file; then restore the .apb with the current build",
		err,
	)
}

// IsWitnessKey classifies a key payload as a sentry key.
func IsWitnessKey(category string) bool {
	return category == CategoryWitness
}

// IsGenericKey classifies a key payload as a generic (no private key)
// LogicSig. Category is authoritative: every canonical payload records one,
// so there is no key-type fallback.
func IsGenericKey(category string) bool {
	return category == CategoryGenericLsig
}

func dsaLogicSigArgBudgetForKey(keyType, baseKeyType string) int {
	return cryptoSignatureSizeForKey(keyType, baseKeyType)
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
	PQScheme               string
	PQAddressSalt          *byte
	BaseKeyType            string
	Parameters             map[string]string
	SigningArgs            []StoredSigningArg
	LogicSigOpcodeProfile  lsigresource.OpcodeProfile
	BoundedAuthorization   *boundedmeta.Metadata
	SigningMetadataVersion int
}
