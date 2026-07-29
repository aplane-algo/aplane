// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/backup/recovered"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// InspectedBackupEntry is one decrypted and canonically validated archive
// entry. The caller owns the plaintext buffers and must call ZeroSecrets.
type InspectedBackupEntry struct {
	Selector     string
	Category     string
	KeyType      string
	KeyJSON      []byte
	TemplateYAML []byte
	TemplateType string
}

// ZeroSecrets clears plaintext credential and template buffers owned by e.
func (e *InspectedBackupEntry) ZeroSecrets() {
	if e == nil {
		return
	}
	crypto.ZeroBytes(e.KeyJSON)
	crypto.ZeroBytes(e.TemplateYAML)
}

// InspectBackupEntry decrypts and validates one standalone .apb entry without
// reading or mutating active destination state.
func (r Restorer) InspectBackupEntry(keysDir, selector string, exportPassphrase []byte) (*InspectedBackupEntry, error) {
	keyJSON, templateYAML, templateType, err := readBackupPayload(keysDir, selector, exportPassphrase)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			crypto.ZeroBytes(keyJSON)
			crypto.ZeroBytes(templateYAML)
		}
	}()

	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		return nil, fmt.Errorf("%w; if this backup predates the current key schema, re-export it with current apstore or regenerate the key", err)
	}
	defer payload.ZeroSecrets()
	derivedSelector, err := payload.Selector()
	if err != nil {
		return nil, err
	}
	if derivedSelector != selector {
		return nil, fmt.Errorf("address mismatch: expected %s, got %s", selector, derivedSelector)
	}
	if err := r.validateKeyTypeAllowed(payload.KeyType); err != nil {
		return nil, err
	}

	canonicalKeyJSON, err := keys.MarshalPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode canonical key payload: %w", err)
	}
	crypto.ZeroBytes(keyJSON)
	keyJSON = canonicalKeyJSON
	success = true
	return &InspectedBackupEntry{
		Selector:     derivedSelector,
		Category:     payload.Category,
		KeyType:      payload.KeyType,
		KeyJSON:      keyJSON,
		TemplateYAML: templateYAML,
		TemplateType: templateType,
	}, nil
}

// RecoverEntry validates an inspected entry against destination template and
// provider state and returns inactive recovered material. It never applies the
// generated restore plans. The caller owns the returned plaintext buffers and
// must call Entry.ZeroSecrets.
func (r Restorer) RecoverEntry(entry *InspectedBackupEntry, masterKey []byte) (*recovered.Entry, error) {
	if entry == nil {
		return nil, fmt.Errorf("inspected backup entry is nil")
	}
	payload, err := keys.ParsePayload(entry.KeyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to revalidate inspected key payload: %w", err)
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		return nil, err
	}
	if selector != entry.Selector || payload.Category != entry.Category || payload.KeyType != entry.KeyType {
		return nil, fmt.Errorf("inspected backup entry metadata no longer matches key payload")
	}
	if err := r.validateKeyTypeAllowed(payload.KeyType); err != nil {
		return nil, err
	}

	signingMeta := payload.SigningMetadata()
	if _, err := r.buildTemplateRestorePlan(
		entry.TemplateYAML,
		payload.KeyType,
		entry.TemplateType,
		masterKey,
		signingMeta.SigningMetadataVersion > 0,
	); err != nil {
		return nil, err
	}
	if _, err := r.buildKeyTypeRestorePlan(
		payload.KeyType,
		len(payload.LogicSigBytecode) > 0,
		masterKey,
		signingMeta,
	); err != nil {
		return nil, err
	}

	return &recovered.Entry{
		Selector:     selector,
		Category:     payload.Category,
		KeyType:      payload.KeyType,
		KeyJSON:      slices.Clone(entry.KeyJSON),
		TemplateYAML: slices.Clone(entry.TemplateYAML),
		TemplateType: entry.TemplateType,
	}, nil
}

// ApplyRecoveredEntry applies one already validated recovered entry to active
// storage. The caller must establish durable rollback intent before calling
// this method.
// ApplyRecoveredEntryWithKeyring applies one recovered entry to the active
// store. Backup still threads a raw key internally and migrates in slice 3,
// so the keyring is unwrapped at this boundary rather than below it.
func (r Restorer) ApplyRecoveredEntryWithKeyring(entry *recovered.Entry, kr *crypto.Keyring) (string, error) {
	masterKey, err := kr.CurrentTermKey()
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(masterKey)
	return r.ApplyRecoveredEntry(entry, masterKey)
}

func (r Restorer) ApplyRecoveredEntry(entry *recovered.Entry, masterKey []byte) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("recovered entry is nil")
	}
	inspected := &InspectedBackupEntry{
		Selector:     entry.Selector,
		Category:     entry.Category,
		KeyType:      entry.KeyType,
		KeyJSON:      entry.KeyJSON,
		TemplateYAML: entry.TemplateYAML,
		TemplateType: entry.TemplateType,
	}
	return r.applyInspectedBackupEntry(inspected, masterKey)
}

// RecoverManagedBackup decrypts selected entries from one identity-managed
// archive and atomically publishes an inactive destination-encrypted batch.
// An empty selectors slice recovers every entry in the archive.
//
// masterKey and exportPassphrase are borrowed and are not cleared.
func RecoverManagedBackup(
	paths storepaths.Paths,
	identityID string,
	archivePath string,
	selectors []string,
	masterKey []byte,
	exportPassphrase []byte,
	role noderole.Role,
) (*recovered.Batch, error) {
	// Boundary adapter: backup migrates in slice 3 and still threads a raw key.
	recoveredKeyring, err := crypto.KeyringFromMasterKeyForMigration(masterKey)
	if err != nil {
		return nil, err
	}
	defer recoveredKeyring.Zero()
	resolvedArchive, err := ResolveManagedBackupPath(paths, identityID, archivePath)
	if err != nil {
		return nil, err
	}
	snapshotPath, archiveSHA256, cleanupSnapshot, err := snapshotManagedBackupArchive(resolvedArchive)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("backup archive not found: %s", resolvedArchive)
		}
		return nil, fmt.Errorf("failed to snapshot backup archive: %w", err)
	}
	defer cleanupSnapshot()

	sourceRoot, cleanupSource, err := PrepareRestoreSource(snapshotPath)
	if err != nil {
		return nil, err
	}
	defer cleanupSource()

	keysDir := ResolveBackupKeysDir(sourceRoot)
	selected, err := normalizeRecoverySelectors(keysDir, selectors)
	if err != nil {
		return nil, err
	}

	// The sealed manifest authenticates the whole archive — member list,
	// source role, and source context — before any of it is read.
	manifest, err := OpenSealedManifest(sourceRoot, exportPassphrase)
	if err != nil {
		return nil, err
	}
	sourceNodeRole := manifest.SourceNodeRole
	sourceProjection := manifest.SourceProjection()
	policyStatus, policySHA256, policyYAML, err := inspectSourcePolicy(sourceRoot, sourceNodeRole)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(policyYAML)

	restorer := NewRestorer(paths, identityID).WithNodeRole(role)
	entries := make([]recovered.Entry, 0, len(selected))
	defer func() {
		for i := range entries {
			entries[i].ZeroSecrets()
		}
	}()
	for _, selector := range selected {
		inspected, err := restorer.InspectBackupEntry(keysDir, selector, exportPassphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect backup entry %s: %w", selector, err)
		}
		recoveredEntry, recoverErr := restorer.RecoverEntry(inspected, masterKey)
		inspected.ZeroSecrets()
		if recoverErr != nil {
			return nil, fmt.Errorf("failed to recover backup entry %s: %w", selector, recoverErr)
		}
		entries = append(entries, *recoveredEntry)
	}

	return recovered.Create(paths, identityID, recovered.CreateRequest{
		ArchiveName:                filepath.Base(resolvedArchive),
		ArchiveSHA256:              archiveSHA256,
		SourceArchiveCreatedAtUnix: manifest.CreatedAtUnix,
		SourceNodeRole:             sourceNodeRole,
		SourcePolicyStatus:         policyStatus,
		SourcePolicySHA256:         policySHA256,
		SourcePolicyYAML:           policyYAML,
		SourceUserAutoApprove:      sourceProjection.UserAutoApprove,
		SourceGenesisHashMappings:  sourceProjection.GenesisHashMappings,
		CreatedAt:                  time.Now().UTC(),
		Entries:                    entries,
	}, recoveredKeyring)
}

func normalizeRecoverySelectors(keysDir string, selectors []string) ([]string, error) {
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
		if selector == "" || filepath.Base(selector) != selector ||
			strings.ContainsAny(selector, `/\`+"\x00") {
			return nil, fmt.Errorf("invalid backup selector %q", selector)
		}
		if i > 0 && selected[i-1] == selector {
			return nil, fmt.Errorf("duplicate backup selector %q", selector)
		}
	}
	return selected, nil
}

func snapshotManagedBackupArchive(archivePath string) (string, string, func(), error) {
	source, err := openManagedBackupArchive(archivePath)
	if err != nil {
		return "", "", nil, err
	}
	defer func() { _ = source.Close() }()

	snapshot, err := os.CreateTemp("", "aplane-recover-*.tar.gz")
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

func inspectSourcePolicy(sourceRoot, sourceNodeRole string) (recovered.SourcePolicyStatus, string, []byte, error) {
	policyPath := filepath.Join(sourceRoot, "policy", "policy.yaml")
	if info, err := os.Stat(policyPath); err == nil && info.Size() > maxSourcePolicyBytes {
		// The policy snapshot is embedded verbatim in the encrypted batch
		// manifest, which every subsequent list/review/activation/rotation
		// decrypts and parses; an unbounded archive-supplied blob must not
		// ride along.
		return "", "", nil, fmt.Errorf("source policy snapshot exceeds size limit %d", maxSourcePolicyBytes)
	}
	policyYAML, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return recovered.SourcePolicyMissing, "", nil, nil
		}
		return "", "", nil, fmt.Errorf("failed to read source policy: %w", err)
	}
	sum := sha256.Sum256(policyYAML)
	digest := hex.EncodeToString(sum[:])

	var parseErr error
	switch sourceNodeRole {
	case string(noderole.RoleSigner):
		_, parseErr = policy.ParseStoredConfig(policyYAML)
	case string(noderole.RoleSentry):
		_, parseErr = policy.ParseStoredSentryConfig(policyYAML)
	case recovered.SourceNodeRoleUnknown:
		return recovered.SourcePolicyUnverified, digest, policyYAML, nil
	default:
		return "", "", nil, fmt.Errorf("unsupported source node role %q", sourceNodeRole)
	}
	if parseErr != nil {
		return recovered.SourcePolicyInvalid, digest, policyYAML, nil
	}
	return recovered.SourcePolicyUnverified, digest, policyYAML, nil
}
