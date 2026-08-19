// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// CredentialEntry is one complete canonical managed credential prepared for
// destination installation. KeyJSON contains private authority and must be
// cleared with ZeroSecrets.
type CredentialEntry struct {
	Selector string
	Category string
	KeyType  string
	KeyJSON  []byte
}

func (e *CredentialEntry) ZeroSecrets() {
	if e == nil {
		return
	}
	crypto.ZeroBytes(e.KeyJSON)
	e.KeyJSON = nil
}

// RestoreSet is a fully authenticated and payload-validated archive selection.
// It is intentionally process-local: direct restore does not publish a second
// destination-encrypted lifecycle outside the generation transaction.
type RestoreSet struct {
	ArchiveName      string
	ArchiveSHA256    string
	SourceNodeRole   string
	ArchiveCreatedAt int64
	Entries          []CredentialEntry
}

// AuthenticatedArchiveError marks a restore failure that occurred only after
// the sealed archive manifest authenticated successfully. Callers use this to
// avoid treating a valid export passphrase as another passphrase guess merely
// because a credential or destination validation failed later.
type AuthenticatedArchiveError struct {
	err error
}

func (e *AuthenticatedArchiveError) Error() string { return e.err.Error() }
func (e *AuthenticatedArchiveError) Unwrap() error { return e.err }

func authenticatedArchiveError(err error) error {
	if err == nil {
		return nil
	}
	return &AuthenticatedArchiveError{err: err}
}

// ArchiveAuthenticated reports whether err proves that the archive manifest
// and export passphrase authenticated before a later validation failure.
func ArchiveAuthenticated(err error) bool {
	var authenticated *AuthenticatedArchiveError
	return errors.As(err, &authenticated)
}

func (s *RestoreSet) ZeroSecrets() {
	if s == nil {
		return
	}
	for i := range s.Entries {
		s.Entries[i].ZeroSecrets()
	}
	s.Entries = nil
}

// RestoreConflict describes an existing destination object that differs from
// an incoming canonical credential or cannot be decoded for equivalence.
type RestoreConflict struct {
	Selector       string
	Category       string
	KeyType        string
	ExistingSHA256 string
	Reason         string
}

// RestoreClassification is destination state pinned under the identity
// mutation lock immediately before generation minting.
type RestoreClassification struct {
	Identical []CredentialEntry
	Pending   []CredentialEntry
	Conflicts []RestoreConflict
}

// LoadManagedRestoreSet snapshots, authenticates, decrypts, canonicalizes, and
// validates every selected archive credential without mutating destination
// storage. An empty selectors slice selects the complete archive.
func LoadManagedRestoreSet(
	paths storepaths.Paths,

	archivePath string,
	selectors []string,
	exportPassphrase []byte,
	role noderole.Role,
) (*RestoreSet, error) {
	resolvedArchive, err := ResolveManagedBackupPath(paths, archivePath)
	if err != nil {
		return nil, err
	}
	snapshotPath, archiveSHA256, cleanupSnapshot, err := snapshotCredentialBackupArchive(resolvedArchive)
	if err != nil {
		return nil, fmt.Errorf("snapshot managed backup: %w", err)
	}
	defer cleanupSnapshot()

	sourceRoot, cleanupSource, err := PrepareRestoreSource(snapshotPath)
	if err != nil {
		return nil, err
	}
	defer cleanupSource()

	manifest, err := OpenSealedManifest(sourceRoot, exportPassphrase)
	if err != nil {
		return nil, err
	}
	keysDir := ResolveBackupKeysDir(sourceRoot)
	if manifest.SourceNodeRole != string(role) {
		return nil, authenticatedArchiveError(fmt.Errorf("backup source node role %q cannot be restored into %q", manifest.SourceNodeRole, role))
	}
	selected, err := normalizeCredentialSelectors(keysDir, selectors)
	if err != nil {
		return nil, authenticatedArchiveError(err)
	}

	set := &RestoreSet{
		ArchiveName:      filepath.Base(resolvedArchive),
		ArchiveSHA256:    archiveSHA256,
		SourceNodeRole:   manifest.SourceNodeRole,
		ArchiveCreatedAt: manifest.CreatedAtUnix,
		Entries:          make([]CredentialEntry, 0, len(selected)),
	}
	success := false
	defer func() {
		if !success {
			set.ZeroSecrets()
		}
	}()
	for _, selector := range selected {
		inspected, inspectErr := inspectCredentialBackupEntry(keysDir, selector, exportPassphrase, role)
		if inspectErr != nil {
			return nil, authenticatedArchiveError(fmt.Errorf("validate backup credential %s: %w", selector, inspectErr))
		}
		if err := validateCredentialRuntimeSupport(&inspected); err != nil {
			inspected.ZeroSecrets()
			return nil, authenticatedArchiveError(fmt.Errorf("validate backup credential %s: %w", selector, err))
		}
		set.Entries = append(set.Entries, inspected)
	}
	success = true
	return set, nil
}

func validateCredentialRuntimeSupport(entry *CredentialEntry) error {
	if entry == nil {
		return fmt.Errorf("credential entry is nil")
	}
	payload, err := keys.ParsePayload(entry.KeyJSON)
	if err != nil {
		return err
	}
	defer payload.ZeroSecrets()
	switch payload.Category {
	case keys.CategoryDSALsig:
		if !lsigprovider.Has(payload.BaseKeyType) {
			return fmt.Errorf(
				"base key type %s is not available for restored key type %s",
				payload.BaseKeyType,
				payload.KeyType,
			)
		}
	case keys.CategoryEd25519, keys.CategoryNativePQ, keys.CategoryGenericLsig, keys.CategoryWitness:
		// Native Ed25519 and witness support is compiled into their node-role
		// runtimes. Generic LogicSig execution uses the bytecode and signing
		// argument contract stored in the credential itself.
	default:
		return fmt.Errorf("unsupported managed credential category %q", payload.Category)
	}
	return nil
}

func inspectCredentialBackupEntry(
	keysDir, selector string,
	exportPassphrase []byte,
	role noderole.Role,
) (CredentialEntry, error) {
	srcFile := filepath.Join(keysDir, selector+".apb")
	// #nosec G304 -- keysDir is the private extracted archive root and selector
	// is restricted to one validated basename before this function is called.
	data, _, err := fsutil.ReadRegularFileLimited(srcFile, crypto.MaxStandaloneEnvelopeBytes)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("read backup file: %w", err)
	}
	if !crypto.IsEncrypted(data) {
		return CredentialEntry{}, fmt.Errorf("backup file must be encrypted")
	}
	var envelope struct {
		EnvelopeVersion int `json:"envelope_version"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return CredentialEntry{}, fmt.Errorf("parse backup envelope: %w", err)
	}
	if envelope.EnvelopeVersion == 1 {
		return CredentialEntry{}, fmt.Errorf(
			"backup uses legacy format (envelope_version 1); create a new credential backup with this release",
		)
	}
	if envelope.EnvelopeVersion != 2 {
		return CredentialEntry{}, fmt.Errorf(
			"unsupported envelope_version: %d; create a new credential backup with this release",
			envelope.EnvelopeVersion,
		)
	}
	plaintext, err := crypto.DecryptStandalone(data, exportPassphrase)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("failed to decrypt backup (wrong passphrase?): %w", err)
	}
	defer crypto.ZeroBytes(plaintext)
	keyJSON, err := ParseBackup(plaintext)
	if err != nil {
		return CredentialEntry{}, err
	}
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		return CredentialEntry{}, err
	}
	defer payload.ZeroSecrets()
	derived, err := payload.Selector()
	if err != nil {
		return CredentialEntry{}, err
	}
	if derived != selector {
		return CredentialEntry{}, fmt.Errorf("selector mismatch: filename=%s derived=%s", selector, derived)
	}
	if err := keyclass.ValidateKeyTypeAllowedForNodeRole(role, payload.KeyType); err != nil {
		return CredentialEntry{}, fmt.Errorf("role-forbidden: %w", err)
	}
	canonical, err := keys.MarshalPayload(payload)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("canonicalize credential: %w", err)
	}
	return CredentialEntry{
		Selector: derived,
		Category: payload.Category,
		KeyType:  payload.KeyType,
		KeyJSON:  canonical,
	}, nil
}

func normalizeCredentialSelectors(keysDir string, selectors []string) ([]string, error) {
	if len(selectors) == 0 {
		var err error
		selectors, err = ScanBackupFiles(keysDir)
		if err != nil {
			return nil, err
		}
	}
	if len(selectors) == 0 {
		return nil, fmt.Errorf("no .apb files found in backup")
	}
	selected := slices.Clone(selectors)
	slices.Sort(selected)
	for i, selector := range selected {
		if selector == "" || filepath.Base(selector) != selector || strings.ContainsAny(selector, `/\`+"\x00") {
			return nil, fmt.Errorf("invalid backup selector %q", selector)
		}
		if i > 0 && selected[i-1] == selector {
			return nil, fmt.Errorf("duplicate backup selector %q", selector)
		}
	}
	return selected, nil
}

func snapshotCredentialBackupArchive(archivePath string) (string, string, func(), error) {
	source, err := openManagedBackupArchive(archivePath)
	if err != nil {
		return "", "", nil, err
	}
	defer func() { _ = source.Close() }()
	snapshot, err := os.CreateTemp("", "aplane-credential-restore-*.tar.gz")
	if err != nil {
		return "", "", nil, err
	}
	snapshotPath := snapshot.Name()
	cleanup := func() { _ = os.Remove(snapshotPath) }
	success := false
	defer func() {
		if !success {
			_ = snapshot.Close()
			cleanup()
		}
	}()
	if err := os.Chmod(snapshotPath, 0o600); err != nil {
		return "", "", nil, err
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(snapshot, hash), source); err != nil {
		return "", "", nil, err
	}
	if err := snapshot.Sync(); err != nil {
		return "", "", nil, err
	}
	if err := snapshot.Close(); err != nil {
		return "", "", nil, err
	}
	success = true
	return snapshotPath, hex.EncodeToString(hash.Sum(nil)), cleanup, nil
}

// ClassifyRestoreSet compares decoded canonical plaintext. An existing object
// that cannot be decrypted or parsed is a replaceable conflict, not an early
// error: this is what permits an explicitly authorized restore to repair a
// damaged credential while the signer remains recovery-blocked.
func ClassifyRestoreSet(
	active storepaths.ActivePaths,
	set *RestoreSet,
	kr *crypto.Keyring,
) (RestoreClassification, error) {
	if set == nil || len(set.Entries) == 0 {
		return RestoreClassification{}, fmt.Errorf("restore set is empty")
	}
	if kr == nil {
		return RestoreClassification{}, fmt.Errorf("destination keyring is required")
	}
	var result RestoreClassification
	for i := range set.Entries {
		entry := set.Entries[i]
		destPath, exists, err := keys.ManagedCredentialDestinationActive(
			active,
			entry.Selector,
			entry.Category,
		)
		if err != nil {
			if isManagedClassConflict(err) {
				result.Conflicts = append(result.Conflicts, RestoreConflict{
					Selector: entry.Selector,
					Category: entry.Category,
					KeyType:  entry.KeyType,
					Reason:   "contradictory managed credential class exists",
				})
				result.Pending = append(result.Pending, entry)
				continue
			}
			return RestoreClassification{}, err
		}
		if !exists {
			result.Pending = append(result.Pending, entry)
			continue
		}
		fingerprint := fileSHA256BestEffort(destPath)
		canonical, compareErr := openCanonicalDestination(destPath, entry, kr)
		if compareErr != nil {
			result.Conflicts = append(result.Conflicts, RestoreConflict{
				Selector:       entry.Selector,
				Category:       entry.Category,
				KeyType:        entry.KeyType,
				ExistingSHA256: fingerprint,
				Reason:         "existing credential is unreadable: " + compareErr.Error(),
			})
			result.Pending = append(result.Pending, entry)
			continue
		}
		equal := bytes.Equal(canonical, entry.KeyJSON)
		crypto.ZeroBytes(canonical)
		if equal {
			result.Identical = append(result.Identical, entry)
			continue
		}
		result.Conflicts = append(result.Conflicts, RestoreConflict{
			Selector:       entry.Selector,
			Category:       entry.Category,
			KeyType:        entry.KeyType,
			ExistingSHA256: fingerprint,
			Reason:         "existing credential differs from backup",
		})
		result.Pending = append(result.Pending, entry)
	}
	return result, nil
}

func openCanonicalDestination(path string, entry CredentialEntry, kr *crypto.Keyring) ([]byte, error) {
	// #nosec G304 -- path is returned by the managed-credential destination
	// resolver from a validated selector and category, never accepted raw.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ctx, err := keys.CredentialContext(entry.Selector, entry.Category)
	if err != nil {
		return nil, err
	}
	plaintext, err := kr.Open(data, ctx)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(plaintext)
	payload, err := keys.ParsePayload(plaintext)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		return nil, err
	}
	if selector != entry.Selector || payload.Category != entry.Category {
		return nil, fmt.Errorf("existing credential metadata does not match its destination")
	}
	return keys.MarshalPayload(payload)
}

func fileSHA256BestEffort(path string) string {
	// #nosec G304 -- callers pass only the managed destination path resolved
	// from a validated credential selector and category.
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func isManagedClassConflict(err error) bool {
	return errors.Is(err, keys.ErrManagedCredentialClassConflict)
}

// ApplyCredentialEntry writes only managed credential authority and derived
// public witness metadata. It never installs templates or changes key-type
// generation state.
func ApplyCredentialEntry(
	active storepaths.ActivePaths,
	entry CredentialEntry,
	kr *crypto.Keyring,
	replaceExisting bool,
) error {
	payload, err := keys.ParsePayload(entry.KeyJSON)
	if err != nil {
		return err
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		return err
	}
	if selector != entry.Selector || payload.Category != entry.Category || payload.KeyType != entry.KeyType {
		return fmt.Errorf("restore entry metadata no longer matches canonical payload")
	}

	destPath, exists, destinationErr := keys.ManagedCredentialDestinationActive(
		active,
		entry.Selector,
		entry.Category,
	)
	if destinationErr != nil && !isManagedClassConflict(destinationErr) {
		return destinationErr
	}
	if (exists || destinationErr != nil) && !replaceExisting {
		return fmt.Errorf("%w: %s", keys.ErrManagedCredentialExists, entry.Selector)
	}
	if destinationErr != nil {
		canonical, err := keys.CanonicalManagedCredentialPathActive(active, entry.Selector, entry.Category)
		if err != nil {
			return err
		}
		destPath = canonical
		otherExt := keys.AccountKeyExtension
		if filepath.Ext(destPath) == keys.AccountKeyExtension {
			otherExt = keys.SentryCredentialExtension
		}
		if err := fsutil.RemoveDurable(filepath.Join(active.KeysDir(), entry.Selector+otherExt)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove contradictory managed credential: %w", err)
		}
	}

	ctx, err := keys.CredentialContext(entry.Selector, entry.Category)
	if err != nil {
		return err
	}
	encrypted, err := kr.Seal(entry.KeyJSON, ctx)
	if err != nil {
		return fmt.Errorf("encrypt restored credential: %w", err)
	}
	if err := fsutil.MkdirAllPrivate(active.KeysDir()); err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(destPath, encrypted); err != nil {
		return fmt.Errorf("write restored credential: %w", err)
	}
	if payload.Category != keys.CategoryWitness {
		_ = fsutil.RemoveDurable(keys.WitnessPublicMetadataPathActive(active, entry.Selector))
	}
	if _, _, err := keys.WriteWitnessPublicMetadataFromKeyJSONActive(
		active,
		entry.Selector,
		entry.KeyJSON,
	); err != nil {
		return fmt.Errorf("write restored witness public metadata: %w", err)
	}
	return nil
}
