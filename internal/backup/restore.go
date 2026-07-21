// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

type RestoreLogger func(format string, args ...any)
type RestoreWarningHandler func(keyType, warning string)

type ManagedBackupInfo struct {
	Path      string
	FileName  string
	CreatedAt time.Time
	Size      int64
	Checksum  string
	Verified  bool
}

type RestorePreview struct {
	ArchivePath string
	Keys        []RestoreKeyInfo
	Errors      []RestoreError
}

type RestoreKeyInfo struct {
	Address       string
	KeyType       string
	AlreadyExists bool
	HasTemplate   bool
	TemplateType  string
	Error         string
}

type RestoreError struct {
	Address string
	Error   string
}

// Restorer restores standalone .apb backup files into an identity keystore.
type Restorer struct {
	Paths      storepaths.Paths
	IdentityID string
	NodeRole   noderole.Role
	Overwrite  bool
	Logf       RestoreLogger
	Warnf      RestoreWarningHandler
}

func NewRestorer(paths storepaths.Paths, identityID string) Restorer {
	return Restorer{Paths: paths, IdentityID: identityID}
}

func (r Restorer) WithLogger(logf RestoreLogger) Restorer {
	r.Logf = logf
	return r
}

func (r Restorer) WithWarningHandler(warnf RestoreWarningHandler) Restorer {
	r.Warnf = warnf
	return r
}

func (r Restorer) WithNodeRole(role noderole.Role) Restorer {
	r.NodeRole = role
	return r
}

func (r Restorer) WithOverwrite(overwrite bool) Restorer {
	r.Overwrite = overwrite
	return r
}

func (r Restorer) nodeRole() noderole.Role {
	if r.NodeRole == "" {
		return noderole.DefaultRole()
	}
	return r.NodeRole
}

func (r Restorer) validateKeyTypeAllowed(keyType string) error {
	if err := keyclass.ValidateKeyTypeAllowedForNodeRole(r.nodeRole(), keyType); err != nil {
		return fmt.Errorf("role-forbidden: %w", err)
	}
	return nil
}

func (r Restorer) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r Restorer) warnSkippedTemplate(keyType, format string, args ...any) {
	warning := fmt.Sprintf("skipped bundled template for %s: %s", keyType, fmt.Sprintf(format, args...))
	r.logf("%s", warning)
	if r.Warnf != nil {
		r.Warnf(keyType, warning)
	}
}

// ResolveBackupKeysDir returns the directory containing .apb files in a backup.
// The current backup archive format uses an apb/ subdirectory.
func ResolveBackupKeysDir(source string) string {
	return filepath.Join(source, "apb")
}

// PrepareRestoreSource returns a directory that can be scanned for restore
// payloads. Archive sources are extracted into a temporary directory that the
// caller must clean up by calling the returned cleanup function.
func PrepareRestoreSource(source string) (string, func(), error) {
	if !IsArchivePath(source) {
		return source, func() {}, nil
	}

	tmpDir, err := os.MkdirTemp("", "apstore-restore-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create archive extraction directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	if err := ExtractTarGzArchive(source, tmpDir); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmpDir, cleanup, nil
}

// ResolveManagedBackupPath validates that archivePath is a supported archive
// below the identity-managed backup directory. A bare filename is resolved
// relative to the identity backup directory.
func ResolveManagedBackupPath(paths storepaths.Paths, identityID, archivePath string) (string, error) {
	return resolveManagedArchivePath(paths.IdentityBackupsDir(identityID), archivePath, "backup")
}

func resolveManagedArchivePath(root, archivePath, label string) (string, error) {
	if archivePath == "" {
		return "", fmt.Errorf("%s archive path is required", label)
	}
	if !IsArchivePath(archivePath) {
		return "", fmt.Errorf("%s archive must end in .tar.gz or .tgz: %s", label, archivePath)
	}

	cleanRoot := filepath.Clean(root)
	candidate := archivePath
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(cleanRoot, candidate)
	}
	candidate = filepath.Clean(candidate)

	rel, err := filepath.Rel(cleanRoot, candidate)
	if err != nil {
		return "", fmt.Errorf("failed to validate %s archive path: %w", label, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s archive is outside managed directory", label)
	}
	if strings.Contains(rel, string(filepath.Separator)) {
		return "", fmt.Errorf("%s archive must be a top-level file in the managed directory", label)
	}
	return candidate, nil
}

// ListManagedBackups returns signer-managed backup archives for an identity,
// newest first.
func ListManagedBackups(paths storepaths.Paths, identityID string) ([]ManagedBackupInfo, error) {
	dir := paths.IdentityBackupsDir(identityID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read managed backup directory: %w", err)
	}

	backups := make([]ManagedBackupInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !IsArchivePath(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("failed to inspect backup archive %s: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		checksum, size, err := FileSHA256(path)
		if err != nil {
			return nil, fmt.Errorf("failed to checksum backup archive %s: %w", entry.Name(), err)
		}
		backups = append(backups, ManagedBackupInfo{
			Path:      path,
			FileName:  entry.Name(),
			CreatedAt: info.ModTime().UTC(),
			Size:      size,
			Checksum:  checksum,
			Verified:  true,
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})
	return backups, nil
}

// DeleteManagedBackup removes a signer-managed backup archive for an identity.
func DeleteManagedBackup(paths storepaths.Paths, identityID, archivePath string) error {
	resolvedArchive, err := ResolveManagedBackupPath(paths, identityID, archivePath)
	if err != nil {
		return err
	}
	if _, err := StatManagedBackupArchive(resolvedArchive); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("backup archive not found: %s", resolvedArchive)
		}
		return fmt.Errorf("failed to inspect backup archive: %w", err)
	}
	if err := os.Remove(resolvedArchive); err != nil {
		return fmt.Errorf("failed to delete backup archive: %w", err)
	}
	return nil
}

// StatManagedBackupArchive returns metadata for a managed backup archive and
// rejects symlinks or non-regular files before extraction.
func StatManagedBackupArchive(archivePath string) (os.FileInfo, error) {
	info, err := os.Lstat(archivePath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("backup archive must be a regular file, not a symlink: %s", archivePath)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("backup archive must be a regular file: %s", archivePath)
	}
	return info, nil
}

func PreviewRestoreWithNodeRole(paths storepaths.Paths, identityID, archivePath string, exportPassphrase []byte, role noderole.Role) (*RestorePreview, error) {
	resolvedArchive, err := ResolveManagedBackupPath(paths, identityID, archivePath)
	if err != nil {
		return nil, err
	}
	if _, err := StatManagedBackupArchive(resolvedArchive); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("backup archive not found: %s", resolvedArchive)
		}
		return nil, fmt.Errorf("failed to inspect backup archive: %w", err)
	}

	sourceRoot, cleanup, err := PrepareRestoreSource(resolvedArchive)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	keysDir := ResolveBackupKeysDir(sourceRoot)
	addresses, err := ScanBackupFiles(keysDir)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no .apb files found in backup: %s", resolvedArchive)
	}

	preview := &RestorePreview{ArchivePath: resolvedArchive}
	for _, address := range addresses {
		keyJSON, templateYAML, tmplType, err := readBackupPayload(keysDir, address, exportPassphrase)
		if err != nil {
			preview.Errors = append(preview.Errors, RestoreError{Error: err.Error()})
			continue
		}
		metadata, err := parseRestoreCredentialMetadata(keyJSON)
		crypto.ZeroBytes(keyJSON)
		if len(templateYAML) > 0 {
			crypto.ZeroBytes(templateYAML)
		}
		if err != nil {
			preview.Errors = append(preview.Errors, RestoreError{Address: address, Error: err.Error()})
			preview.Keys = append(preview.Keys, RestoreKeyInfo{Address: address, Error: err.Error()})
			continue
		}
		if metadata.selector != address {
			errMsg := fmt.Sprintf("address mismatch: expected %s, got %s", address, metadata.selector)
			preview.Errors = append(preview.Errors, RestoreError{Address: address, Error: errMsg})
			preview.Keys = append(preview.Keys, RestoreKeyInfo{Address: address, KeyType: metadata.keyType, Error: errMsg})
			continue
		}
		if roleErr := keyclass.ValidateKeyTypeAllowedForNodeRole(role, metadata.keyType); roleErr != nil {
			errMsg := fmt.Sprintf("role-forbidden: %v", roleErr)
			preview.Errors = append(preview.Errors, RestoreError{Address: address, Error: errMsg})
			preview.Keys = append(preview.Keys, RestoreKeyInfo{
				Address:      address,
				KeyType:      metadata.keyType,
				HasTemplate:  len(templateYAML) > 0,
				TemplateType: tmplType,
				Error:        errMsg,
			})
			continue
		}
		_, alreadyExists, destinationErr := keys.ManagedCredentialDestination(paths, identityID, address, metadata.category)
		if destinationErr != nil {
			errMsg := destinationErr.Error()
			preview.Errors = append(preview.Errors, RestoreError{Address: address, Error: errMsg})
			preview.Keys = append(preview.Keys, RestoreKeyInfo{
				Address:      address,
				KeyType:      metadata.keyType,
				HasTemplate:  len(templateYAML) > 0,
				TemplateType: tmplType,
				Error:        errMsg,
			})
			continue
		}
		preview.Keys = append(preview.Keys, RestoreKeyInfo{
			Address:       address,
			KeyType:       metadata.keyType,
			AlreadyExists: alreadyExists,
			HasTemplate:   len(templateYAML) > 0,
			TemplateType:  tmplType,
		})
	}
	return preview, nil
}

func readBackupPayload(keysDir, address string, exportPassphrase []byte) (keyJSON []byte, templateYAML []byte, templateType string, err error) {
	srcFile := filepath.Join(keysDir, address+".apb")

	data, err := os.ReadFile(srcFile)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to read backup file: %w", err)
	}

	if !crypto.IsEncrypted(data) {
		return nil, nil, "", fmt.Errorf("backup file must be encrypted")
	}
	var envelope struct {
		EnvelopeVersion int `json:"envelope_version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse backup file: %w", err)
	}

	var decryptedData []byte
	switch envelope.EnvelopeVersion {
	case 2:
		decryptedData, err = crypto.DecryptStandalone(data, exportPassphrase)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to decrypt backup (wrong passphrase?): %w", err)
		}
	case 1:
		return nil, nil, "", fmt.Errorf("backup uses legacy format (envelope_version 1); re-export with current apstore")
	default:
		return nil, nil, "", fmt.Errorf("unsupported envelope_version: %d", envelope.EnvelopeVersion)
	}

	defer crypto.ZeroBytes(decryptedData)
	keyJSON, templateYAML, templateType, err = ParseBackup(decryptedData)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse backup payload: %w", err)
	}

	keyCopy := append([]byte(nil), keyJSON...)
	templateCopy := append([]byte(nil), templateYAML...)
	return keyCopy, templateCopy, templateType, nil
}

// RestoreKey restores one .apb backup file into the restorer identity.
// keysDir is the directory containing .apb backup files. Backup files use
// standalone encryption (envelope_version 2) and are decrypted with the export
// passphrase. Restored key files use master-key encryption.
//
// Backup files may contain a BackupBundle (key plus embedded template) or a
// plain canonical key payload.
func (r Restorer) RestoreKey(keysDir, address string, masterKey, exportPassphrase []byte) (string, error) {
	keyJSON, templateYAML, tmplType, err := readBackupPayload(keysDir, address, exportPassphrase)
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(keyJSON)
	defer crypto.ZeroBytes(templateYAML)

	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		return "", fmt.Errorf("%w; if this backup predates the current key schema, re-export it with current apstore or regenerate the key", err)
	}
	defer payload.ZeroSecrets()
	derivedAddress, err := payload.Selector()
	if err != nil {
		return "", err
	}
	keyType := payload.KeyType
	hasLogicSigBytecode := len(payload.LogicSigBytecode) > 0

	if derivedAddress != address {
		return "", fmt.Errorf("address mismatch: expected %s, got %s", address, derivedAddress)
	}
	if err := r.validateKeyTypeAllowed(keyType); err != nil {
		return "", err
	}
	destPath, alreadyExists, err := keys.ManagedCredentialDestination(r.Paths, r.IdentityID, address, payload.Category)
	if err != nil {
		return "", err
	}
	if alreadyExists && !r.Overwrite {
		return "", fmt.Errorf("%w: %s", keys.ErrManagedCredentialExists, destPath)
	}

	signingMeta := payload.SigningMetadata()
	templateFingerprint := ""
	if len(templateYAML) > 0 {
		templateFingerprint, _ = bundledTemplateFingerprint(templateYAML, tmplType)
	}
	templateRestorePlan, err := r.buildTemplateRestorePlan(templateYAML, keyType, tmplType, masterKey, signingMeta.SigningMetadataVersion > 0)
	if err != nil {
		return "", err
	}
	keyTypeRestorePlan, err := r.buildKeyTypeRestorePlan(keyType, hasLogicSigBytecode, masterKey, signingMeta)
	if err != nil {
		return "", err
	}

	var rollbacks []func() error
	applyPlan := func(plan restorePlan) error {
		rollback, err := plan.Apply()
		if err != nil {
			return err
		}
		if rollback != nil {
			rollbacks = append([]func() error{rollback}, rollbacks...)
		}
		return nil
	}
	rollbackPlans := func(cause error) error {
		var rollbackErrs []string
		for _, rollback := range rollbacks {
			if rollback == nil {
				continue
			}
			if err := rollback(); err != nil {
				rollbackErrs = append(rollbackErrs, err.Error())
			}
		}
		if len(rollbackErrs) == 0 {
			return cause
		}
		return fmt.Errorf("%w (rollback failed: %s)", cause, strings.Join(rollbackErrs, "; "))
	}

	if err := applyPlan(templateRestorePlan); err != nil {
		return "", rollbackPlans(fmt.Errorf("failed to prepare template state for %s: %w", address, err))
	}
	if err := applyPlan(keyTypeRestorePlan); err != nil {
		return "", rollbackPlans(fmt.Errorf("failed to prepare key type state for %s: %w", address, err))
	}

	keyPayload := keyJSON
	if templateFingerprint != "" {
		annotated, changed, err := annotateMissingTemplateFingerprint(payload, templateFingerprint)
		if err != nil {
			return "", rollbackPlans(fmt.Errorf("failed to annotate template fingerprint for %s: %w", address, err))
		}
		if changed {
			defer crypto.ZeroBytes(annotated)
			keyPayload = annotated
		}
	}

	encrypted, err := crypto.EncryptWithMasterKey(keyPayload, masterKey)
	if err != nil {
		return "", rollbackPlans(fmt.Errorf("failed to encrypt key: %w", err))
	}

	if err := fsutil.MkdirAll(r.Paths.KeysDir(r.IdentityID)); err != nil {
		return "", rollbackPlans(fmt.Errorf("failed to create keys directory: %w", err))
	}
	if err := fsutil.WriteFile(destPath, encrypted); err != nil {
		return "", rollbackPlans(fmt.Errorf("failed to write key file: %w", err))
	}
	componentMetadataPath, wroteComponentMetadata, err := keys.WriteWitnessPublicMetadataFromKeyJSON(r.Paths, r.IdentityID, address, keyPayload)
	if err != nil {
		_ = os.Remove(destPath)
		return "", rollbackPlans(fmt.Errorf("failed to write component public metadata for %s: %w", address, err))
	}
	if wroteComponentMetadata {
		rollbacks = append([]func() error{
			func() error {
				return os.Remove(componentMetadataPath)
			},
		}, rollbacks...)
	}

	return keyType, nil
}

func bundledTemplateFingerprint(templateYAML []byte, tmplType string) (string, error) {
	if len(templateYAML) == 0 {
		return "", nil
	}
	tt := templatestore.TemplateType(tmplType)
	if tt == "" {
		tt = templatestore.TemplateTypeGeneric
	}
	switch tt {
	case templatestore.TemplateTypeGeneric, templatestore.TemplateTypeComposed:
	default:
		return "", fmt.Errorf("unsupported template type: %s", tmplType)
	}
	return templateCompatibilityFingerprint(tt, templateYAML)
}

// annotateMissingTemplateFingerprint stamps the bundled template fingerprint
// onto the already-parsed restore payload when it lacks one and returns the
// canonical re-encoding. changed=false means the original key JSON stands.
func annotateMissingTemplateFingerprint(payload *keys.Payload, fingerprint string) ([]byte, bool, error) {
	if payload.TemplateFingerprint != "" {
		return nil, false, nil
	}
	payload.TemplateFingerprint = fingerprint
	annotated, err := keys.MarshalPayload(payload)
	if err != nil {
		return nil, false, err
	}
	return annotated, true, nil
}

// RestoreKeyMetadata reads key metadata needed for restore validation.
func RestoreKeyMetadata(keyJSON []byte) (keyType string, address string, hasLogicSigBytecode bool, err error) {
	metadata, err := parseRestoreCredentialMetadata(keyJSON)
	if err != nil {
		return "", "", false, err
	}
	return metadata.keyType, metadata.selector, metadata.hasLogicSigBytecode, nil
}

type restoreCredentialMetadata struct {
	keyType             string
	selector            string
	category            string
	hasLogicSigBytecode bool
}

func parseRestoreCredentialMetadata(keyJSON []byte) (restoreCredentialMetadata, error) {
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		return restoreCredentialMetadata{}, fmt.Errorf("failed to parse key file: %w", err)
	}
	defer payload.ZeroSecrets()
	if err := validateBackupKeyType(payload.KeyType); err != nil {
		return restoreCredentialMetadata{}, err
	}
	selector, err := payload.Selector()
	if err != nil {
		return restoreCredentialMetadata{}, err
	}
	return restoreCredentialMetadata{
		keyType:             payload.KeyType,
		selector:            selector,
		category:            payload.Category,
		hasLogicSigBytecode: len(payload.LogicSigBytecode) > 0,
	}, nil
}

// RestoreTemplate saves a template extracted from a backup bundle to the
// identity template store.
func (r Restorer) RestoreTemplate(templateYAML []byte, keyType, tmplType string, masterKey []byte) error {
	if err := r.validateKeyTypeAllowed(keyType); err != nil {
		return err
	}
	restorePlan, err := r.buildTemplateRestorePlan(templateYAML, keyType, tmplType, masterKey, false)
	if err != nil {
		return err
	}
	_, err = restorePlan.Apply()
	return err
}

type restorePlan struct {
	apply func() (func() error, error)
}

func (p restorePlan) Apply() (func() error, error) {
	if p.apply == nil {
		return nil, nil
	}
	return p.apply()
}

func (r Restorer) buildTemplateRestorePlan(templateYAML []byte, keyType, tmplType string, masterKey []byte, standaloneSigningMetadata bool) (restorePlan, error) {
	if err := validateBackupKeyType(keyType); err != nil {
		return restorePlan{}, err
	}

	if templateYAML == nil {
		if standaloneSigningMetadata {
			return restorePlan{}, nil
		}
		if existingType, _, ok, err := r.loadKeystoreTemplateForKeyType(keyType, masterKey); err != nil {
			return restorePlan{}, err
		} else if ok {
			if r.keyTypeRecordDisabled(keyType) {
				return r.enableInstalledTemplatePlan(keyType, existingType, masterKey), nil
			}
			return restorePlan{}, nil
		}
		if authType, _, ok, err := r.authoritativeTemplateForKeyType(keyType); err != nil {
			return restorePlan{}, err
		} else if ok {
			return r.installLibraryTemplatePlan(keyType, authType, masterKey), nil
		}
		return restorePlan{}, nil
	}

	tt := templatestore.TemplateType(tmplType)
	if tt == "" {
		tt = templatestore.TemplateTypeGeneric
	}
	switch tt {
	case templatestore.TemplateTypeGeneric, templatestore.TemplateTypeComposed:
	default:
		if standaloneSigningMetadata {
			r.warnSkippedTemplate(keyType, "unsupported template type %s", tmplType)
			return restorePlan{}, nil
		}
		return restorePlan{}, fmt.Errorf("unsupported template type: %s", tmplType)
	}

	incomingFingerprint, err := templateCompatibilityFingerprint(tt, templateYAML)
	if err != nil {
		if standaloneSigningMetadata {
			r.warnSkippedTemplate(keyType, "failed to fingerprint incoming template: %v", err)
			return restorePlan{}, nil
		}
		return restorePlan{}, fmt.Errorf("failed to fingerprint incoming template: %w", err)
	}

	if authType, authYAML, ok, err := r.authoritativeTemplateForKeyType(keyType); err != nil {
		return restorePlan{}, err
	} else if ok {
		if authType != tt {
			if standaloneSigningMetadata {
				r.warnSkippedTemplate(keyType, "backup type %s conflicts with authoritative local type %s", tt, authType)
				return restorePlan{}, nil
			}
			return restorePlan{}, fmt.Errorf("template conflict for %s: backup type %s does not match authoritative local type %s", keyType, tt, authType)
		}
		authFingerprint, err := templateCompatibilityFingerprint(authType, authYAML)
		if err != nil {
			return restorePlan{}, fmt.Errorf("failed to fingerprint authoritative local template: %w", err)
		}
		if templateFingerprintsConflict(authFingerprint, incomingFingerprint) {
			if standaloneSigningMetadata {
				r.warnSkippedTemplate(keyType, "backup template conflicts with authoritative local definition")
				return restorePlan{}, nil
			}
			return restorePlan{}, fmt.Errorf("template conflict for %s: backup template does not match authoritative local definition", keyType)
		}
		if existingType, existingYAML, exists, err := r.loadKeystoreTemplateForKeyType(keyType, masterKey); err != nil {
			return restorePlan{}, err
		} else if exists {
			if existingType != authType {
				if standaloneSigningMetadata {
					r.warnSkippedTemplate(keyType, "existing keystore type %s conflicts with authoritative local type %s", existingType, authType)
					return restorePlan{}, nil
				}
				return restorePlan{}, fmt.Errorf("template conflict for %s: existing keystore type %s does not match authoritative local type %s", keyType, existingType, authType)
			}
			existingFingerprint, err := templateCompatibilityFingerprint(existingType, existingYAML)
			if err != nil {
				return restorePlan{}, fmt.Errorf("failed to fingerprint existing keystore template: %w", err)
			}
			if templateFingerprintsConflict(existingFingerprint, authFingerprint) {
				if standaloneSigningMetadata {
					r.warnSkippedTemplate(keyType, "existing keystore template conflicts with authoritative local definition")
					return restorePlan{}, nil
				}
				return restorePlan{}, fmt.Errorf("template conflict for %s: existing keystore template does not match authoritative local definition", keyType)
			}
			if r.keyTypeRecordDisabled(keyType) {
				return r.enableInstalledTemplatePlan(keyType, existingType, masterKey), nil
			}
			return restorePlan{}, nil
		}
		return r.installLibraryTemplatePlan(keyType, authType, masterKey), nil
	}

	if existingType, existingYAML, ok, err := r.loadKeystoreTemplateForKeyType(keyType, masterKey); err != nil {
		return restorePlan{}, err
	} else if ok {
		if existingType != tt {
			if standaloneSigningMetadata {
				r.warnSkippedTemplate(keyType, "backup type %s conflicts with existing keystore type %s", tt, existingType)
				return restorePlan{}, nil
			}
			return restorePlan{}, fmt.Errorf("template conflict for %s: backup type %s does not match existing keystore type %s", keyType, tt, existingType)
		}
		existingFingerprint, err := templateCompatibilityFingerprint(existingType, existingYAML)
		if err != nil {
			return restorePlan{}, fmt.Errorf("failed to fingerprint existing keystore template: %w", err)
		}
		if templateFingerprintsConflict(existingFingerprint, incomingFingerprint) {
			if standaloneSigningMetadata {
				r.warnSkippedTemplate(keyType, "backup template conflicts with existing keystore definition")
				return restorePlan{}, nil
			}
			return restorePlan{}, fmt.Errorf("template conflict for %s: backup template does not match existing keystore definition", keyType)
		}
		if r.keyTypeRecordDisabled(keyType) {
			return r.enableInstalledTemplatePlan(keyType, existingType, masterKey), nil
		}
		return restorePlan{}, nil
	}

	if lsigprovider.Has(keyType) {
		if standaloneSigningMetadata {
			r.warnSkippedTemplate(keyType, "key type is already provided by this binary")
			return restorePlan{}, nil
		}
		return restorePlan{}, fmt.Errorf("template conflict for %s: key type is already provided by a built-in non-template provider", keyType)
	}

	return r.installIncomingTemplatePlan(keyType, tt, templateYAML, masterKey), nil
}

func (r Restorer) buildKeyTypeRestorePlan(keyType string, hasLogicSigBytecode bool, masterKey []byte, signingMeta keys.SigningMetadata) (restorePlan, error) {
	if err := validateBackupKeyType(keyType); err != nil {
		return restorePlan{}, err
	}

	if !hasLogicSigBytecode {
		return restorePlan{}, nil
	}
	// ParsePayload guarantees lsig payloads carry the current signing metadata
	// version, so no missing-metadata branch is needed here.

	if keytypecatalog.IsLibraryVisible(keyType) {
		if !lsigprovider.Has(keyType) {
			return restorePlan{}, fmt.Errorf("key type %s is library-visible but is not registered in this binary", keyType)
		}
		return r.activateCompiledProviderPlan(keyType, masterKey), nil
	}

	if signingMeta.Category == keys.CategoryGenericLsig {
		return restorePlan{}, nil
	}
	baseKeyType := signingMeta.BaseKeyType
	if baseKeyType == "" {
		baseKeyType = keyType
	}
	if !lsigprovider.Has(baseKeyType) {
		return restorePlan{}, fmt.Errorf("base key type %s is not available for restored key type %s", baseKeyType, keyType)
	}
	return restorePlan{}, nil
}

func (r Restorer) authoritativeTemplateForKeyType(keyType string) (templatestore.TemplateType, []byte, bool, error) {
	if err := validateBackupKeyType(keyType); err != nil {
		return "", nil, false, err
	}
	if !isBackupTemplateKeyType(keyType) {
		return "", nil, false, nil
	}

	libraryPath := filepath.Join(r.Paths.TemplateLibraryDir(), keyType+".yaml")
	if _, err := os.Stat(libraryPath); err == nil {
		parsed, err := templatelibrary.ParseFile(libraryPath)
		if err != nil {
			return "", nil, false, fmt.Errorf("failed to parse authoritative library template %s: %w", keyType, err)
		}
		if !strings.EqualFold(parsed.KeyType, keyType) {
			return "", nil, false, fmt.Errorf("authoritative library template %s declares key type %s", keyType, parsed.KeyType)
		}
		return parsed.TemplateType, parsed.YAMLData, true, nil
	} else if !os.IsNotExist(err) {
		return "", nil, false, fmt.Errorf("failed to inspect authoritative library template %s: %w", keyType, err)
	}
	return "", nil, false, nil
}

func (r Restorer) loadKeystoreTemplateForKeyType(keyType string, masterKey []byte) (templatestore.TemplateType, []byte, bool, error) {
	for _, tt := range templatestore.ActiveTemplateTypes() {
		if !templatestore.TemplateExistsForPaths(r.Paths, r.IdentityID, keyType, tt) {
			continue
		}
		templatePath := templatestore.GetTemplateFilePathForPaths(r.Paths, r.IdentityID, keyType, tt)
		templateYAML, err := templatestore.LoadTemplateFromPath(templatePath, masterKey)
		if err != nil {
			return "", nil, false, fmt.Errorf("failed to read existing keystore template: %w", err)
		}
		return tt, templateYAML, true, nil
	}
	return "", nil, false, nil
}

func (r Restorer) enableInstalledTemplatePlan(keyType string, templateType templatestore.TemplateType, masterKey []byte) restorePlan {
	_ = masterKey
	return restorePlan{apply: func() (func() error, error) {
		prior, priorOK, err := keytypestate.Get(r.Paths, r.IdentityID, keyType)
		if err != nil {
			return nil, err
		}
		if !priorOK {
			return nil, fmt.Errorf("template state not found for %s", keyType)
		}
		if prior.State == keytypestate.StateEnabled {
			return nil, nil
		}
		if err := keytypestate.SetState(r.Paths, r.IdentityID, keyType, keytypestate.StateEnabled); err != nil {
			return nil, err
		}
		r.logf("enabled template: %s (%s)", keyType, templateType)
		return func() error {
			prior.State = keytypestate.StateDisabled
			return keytypestate.Put(r.Paths, r.IdentityID, prior)
		}, nil
	}}
}

func (r Restorer) installLibraryTemplatePlan(keyType string, templateType templatestore.TemplateType, masterKey []byte) restorePlan {
	return restorePlan{apply: func() (func() error, error) {
		prior, priorOK, err := keytypestate.Get(r.Paths, r.IdentityID, keyType)
		if err != nil {
			return nil, err
		}
		hadTemplate := templatestore.TemplateExistsForPaths(r.Paths, r.IdentityID, keyType, templateType)
		result, err := templatelibrary.InstallFromLibrary(r.Paths, r.IdentityID, templatelibrary.TemplateRef{
			KeyType:      keyType,
			TemplateType: templateType,
		}, masterKey)
		if err != nil {
			return nil, err
		}
		if !result.AlreadyExists || (priorOK && prior.State == keytypestate.StateDisabled) {
			r.logf("restored template: %s (%s)", keyType, templateType)
		}
		return func() error {
			if !hadTemplate {
				if err := removeTemplateFile(r.Paths, r.IdentityID, keyType, templateType); err != nil {
					return err
				}
			}
			return r.restoreKeyTypeRecord(keyType, prior, priorOK)
		}, nil
	}}
}

func (r Restorer) installIncomingTemplatePlan(keyType string, templateType templatestore.TemplateType, templateYAML, masterKey []byte) restorePlan {
	return restorePlan{apply: func() (func() error, error) {
		prior, priorOK, err := keytypestate.Get(r.Paths, r.IdentityID, keyType)
		if err != nil {
			return nil, err
		}
		hadTemplate := templatestore.TemplateExistsForPaths(r.Paths, r.IdentityID, keyType, templateType)
		parsed, err := templatelibrary.ParseYAMLAs("", templateYAML, templateType)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bundled template: %w", err)
		}
		if !strings.EqualFold(parsed.KeyType, keyType) {
			return nil, fmt.Errorf("bundled template for %s declares key type %s", keyType, parsed.KeyType)
		}
		result, err := templatelibrary.InstallParsed(r.Paths, r.IdentityID, parsed, masterKey)
		if err != nil {
			return nil, err
		}
		if !result.AlreadyExists || (priorOK && prior.State == keytypestate.StateDisabled) {
			r.logf("restored template: %s (%s)", keyType, templateType)
		}
		return func() error {
			if !hadTemplate {
				if err := removeTemplateFile(r.Paths, r.IdentityID, keyType, templateType); err != nil {
					return err
				}
			}
			return r.restoreKeyTypeRecord(keyType, prior, priorOK)
		}, nil
	}}
}

func (r Restorer) activateCompiledProviderPlan(keyType string, masterKey []byte) restorePlan {
	return restorePlan{apply: func() (func() error, error) {
		prior, priorOK, err := keytypestate.Get(r.Paths, r.IdentityID, keyType)
		if err != nil {
			return nil, err
		}
		rec, err := r.compiledProviderRecord(keyType)
		if err != nil {
			return nil, err
		}
		if priorOK && prior.Source == keytypestate.SourceCompiled &&
			prior.State == keytypestate.StateEnabled &&
			templateFingerprintsEquivalent(prior.Fingerprint, rec.Fingerprint) {
			r.logf("key type already active: %s", keyType)
			return nil, nil
		}
		if priorOK && (prior.Source != keytypestate.SourceCompiled || !templateFingerprintsEquivalent(prior.Fingerprint, rec.Fingerprint)) {
			if err := keytypestate.RequireUnused(r.Paths, r.IdentityID, keyType, masterKey); err != nil {
				return nil, err
			}
		}
		if err := keytypestate.Put(r.Paths, r.IdentityID, rec); err != nil {
			return nil, err
		}
		r.logf("activated key type: %s", keyType)
		return func() error {
			return r.restoreKeyTypeRecord(keyType, prior, priorOK)
		}, nil
	}}
}

func (r Restorer) keyTypeRecordDisabled(keyType string) bool {
	rec, ok, err := keytypestate.Get(r.Paths, r.IdentityID, keyType)
	return err == nil && ok && rec.State == keytypestate.StateDisabled
}

func (r Restorer) restoreKeyTypeRecord(keyType string, prior keytypestate.Record, priorOK bool) error {
	if priorOK {
		return keytypestate.Put(r.Paths, r.IdentityID, prior)
	}
	return keytypestate.Delete(r.Paths, r.IdentityID, keyType)
}

func (r Restorer) compiledProviderRecord(keyType string) (keytypestate.Record, error) {
	provider := lsigprovider.Get(keyType)
	if provider == nil {
		return keytypestate.Record{}, fmt.Errorf("key type %s is not registered", keyType)
	}
	fingerprint, _ := lsigprovider.CompatibilityFingerprintOf(provider)
	return keytypestate.Record{
		KeyType:     keyType,
		Source:      keytypestate.SourceCompiled,
		State:       keytypestate.StateEnabled,
		Fingerprint: fingerprint,
	}, nil
}

func removeTemplateFile(paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType) error {
	path := templatestore.GetTemplateFilePathForPaths(paths, identityID, keyType, templateType)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove restored template: %w", err)
	}
	return nil
}

// templateFingerprintsConflict reports a real template-provenance conflict:
// two fingerprints that are comparable (same format version) yet hash
// differently. A cross-version or unparseable pair is "not comparable" and is
// never reported as a conflict, so a future fingerprint-formula bump cannot
// spuriously fail a restore. The bundled-template bytecode-reproduction check in
// verify.go remains the real safety gate for bundled template claims.
func templateFingerprintsConflict(a, b string) bool {
	match, comparable := lsigprovider.FingerprintsMatch(a, b)
	return comparable && !match
}

// templateFingerprintsEquivalent reports that two fingerprints are comparable
// (same format version) and hash identically. A cross-version or unparseable
// pair is not equivalent (forcing a benign re-pin rather than a false match).
func templateFingerprintsEquivalent(a, b string) bool {
	match, _ := lsigprovider.FingerprintsMatch(a, b)
	return match
}

func templateCompatibilityFingerprint(templateType templatestore.TemplateType, templateYAML []byte) (string, error) {
	switch templateType {
	case templatestore.TemplateTypeGeneric:
		return generictemplate.SemanticFingerprint(templateYAML)
	case templatestore.TemplateTypeComposed:
		return composeddsa.SemanticFingerprint(templateYAML)
	default:
		return "", fmt.Errorf("unsupported template type: %s", templateType)
	}
}
