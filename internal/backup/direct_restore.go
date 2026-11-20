// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keyclass"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// CredentialEntry is one archived credential as loadCredentialEntry admitted
// it, prepared for destination installation. Its selector, canonical key JSON
// and payload come from that one parse and are unexported, so an entry
// cannot name a selector or category its credential does not have. The key
// JSON contains private authority and must be cleared with ZeroSecrets.
// Policy is the credential's archived policy document of its own, nil when
// the archive carries none.
type CredentialEntry struct {
	StageHint *RotatingStageHint
	Policy    []byte
	// credential is shared by every copy of the entry, so clearing it
	// through one copy clears it for all: restore applies the copies
	// ClassifyRestoreSet returns, not the set's own entries.
	credential *admittedCredential
}

// admittedCredential is what admitCredentialEntry established about one
// credential.
type admittedCredential struct {
	selector string
	keyJSON  []byte
	// payload is the admitted payload with its secrets cleared: the
	// category, key type, public key and genesis hash later steps read.
	payload *keys.Payload
}

// Selector is the credential's canonical selector, derived from its payload.
func (e *CredentialEntry) Selector() string {
	if e.credential == nil {
		return ""
	}
	return e.credential.selector
}

// Category is the credential's payload category.
func (e *CredentialEntry) Category() string {
	if e.credential == nil {
		return ""
	}
	return e.credential.payload.Category
}

// KeyType is the credential's key type.
func (e *CredentialEntry) KeyType() string {
	if e.credential == nil {
		return ""
	}
	return e.credential.payload.KeyType
}

// keyJSON is the canonical credential, nil once it was cleared.
func (e *CredentialEntry) keyJSON() []byte {
	if e.credential == nil {
		return nil
	}
	return e.credential.keyJSON
}

func (e *CredentialEntry) ZeroSecrets() {
	if e == nil || e.credential == nil {
		return
	}
	crypto.ZeroBytes(e.credential.keyJSON)
	e.credential.keyJSON = nil
}

// RestoreSet is a fully authenticated archive selection: the credentials
// this node admits, and the ones it skips. It is intentionally process-local:
// direct restore does not publish a second destination-encrypted lifecycle
// outside the generation transaction.
type RestoreSet struct {
	ArchiveName      string
	ArchiveSHA256    string
	SourceNodeRole   string
	ArchiveCreatedAt int64
	Entries          []CredentialEntry
	// Skipped lists the selected credentials this node cannot admit.
	Skipped []SkippedEntry
}

// SkippedEntry is an archived credential this node cannot admit, and why.
// Its archived policy is skipped with it.
type SkippedEntry struct {
	Selector string
	Reason   string
}

// SkipRefusalError refuses a restore or rebuild for what admission would
// skip: a credential the request named, or every credential the archive
// holds. An explicit selection is never narrowed, and a restore with nothing
// to restore is no restore.
type SkipRefusalError struct {
	// Skipped is never empty: only loadRestoreSet refuses, and only for
	// what it skipped.
	Skipped []SkippedEntry
	// Named reports that the request named its credentials, so each skipped
	// one is a credential it asked for.
	Named bool
}

func (e *SkipRefusalError) Error() string {
	first := e.Skipped[0].Selector + ": " + e.Skipped[0].Reason
	switch {
	case e.Named && len(e.Skipped) == 1:
		return "selected credential cannot be restored: " + first
	case e.Named:
		return fmt.Sprintf("%d selected credentials cannot be restored; first %s", len(e.Skipped), first)
	case len(e.Skipped) == 1:
		return "nothing to restore: the backup's only credential is skipped: " + first
	default:
		return fmt.Sprintf("nothing to restore: all %d credentials in the backup are skipped; first %s", len(e.Skipped), first)
	}
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
// mutation lock immediately before generation minting. Policies lists the
// entries whose archived policy must be installed, whether or not their
// credential is pending.
type RestoreClassification struct {
	Identical []CredentialEntry
	Pending   []CredentialEntry
	Policies  []CredentialEntry
	Conflicts []RestoreConflict
}

// LoadManagedRestoreSet snapshots and authenticates a managed archive and
// admits each selected credential without mutating destination storage. An
// empty selectors slice selects the complete archive. A credential this node
// cannot admit is skipped and listed in the set, unless the request named it
// or nothing would be left to restore: a SkipRefusalError then refuses the
// whole restore.
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

	archive, err := openArchive(sourceRoot, exportPassphrase)
	if err != nil {
		return nil, err
	}
	if err := archive.requireSourceRole(role); err != nil {
		return nil, err
	}
	set, err := archive.loadRestoreSet(selectors, exportPassphrase, role)
	if err != nil {
		return nil, authenticatedArchiveError(err)
	}
	set.ArchiveName = filepath.Base(resolvedArchive)
	set.ArchiveSHA256 = archiveSHA256
	return set, nil
}

// LoadRebuildSet admits the selected credentials of an extracted archive for
// a fresh store of role, as LoadManagedRestoreSet does for a live one. The
// role may differ from the archive's source role.
func LoadRebuildSet(sourceRoot string, selectors []string, exportPassphrase []byte, role noderole.Role) (*RestoreSet, error) {
	archive, err := openArchive(sourceRoot, exportPassphrase)
	if err != nil {
		return nil, err
	}
	return archive.loadRestoreSet(selectors, exportPassphrase, role)
}

// openedArchive is an extracted archive whose sealed manifest authenticated,
// with the selectors of the credentials it holds.
type openedArchive struct {
	keysDir   string
	manifest  Manifest
	selectors []string
}

// openArchive authenticates an extracted archive against its sealed manifest
// and checks its structure: it holds a credential, and each policy it holds
// belongs to one. A failure after the manifest authenticated is an
// AuthenticatedArchiveError.
func openArchive(sourceRoot string, exportPassphrase []byte) (openedArchive, error) {
	manifest, err := OpenSealedManifest(sourceRoot, exportPassphrase)
	if err != nil {
		return openedArchive{}, withArchivePaths(sourceRoot, err)
	}
	archive := openedArchive{keysDir: ResolveBackupKeysDir(sourceRoot), manifest: manifest}
	if archive.selectors, err = archiveSelectors(archive.keysDir); err != nil {
		return openedArchive{}, authenticatedArchiveError(withArchivePaths(sourceRoot, err))
	}
	return archive, nil
}

// archiveSelectors lists the credentials an extracted archive holds, sorted,
// refusing a policy that belongs to none of them. A member whose name is not
// its credential's selector is admission's to skip.
func archiveSelectors(keysDir string) ([]string, error) {
	selectors, err := ScanBackupFiles(keysDir)
	if err != nil {
		return nil, err
	}
	if len(selectors) == 0 {
		return nil, fmt.Errorf("no .apb files found in backup")
	}
	// The scan is in file-name order, which is not selector order when one
	// selector extends another with a byte below '.': "A-B.apb" sorts before
	// "A.apb". The searches below need selector order.
	slices.Sort(selectors)
	keysWithPolicy, err := scanBackupPolicies(keysDir)
	if err != nil {
		return nil, err
	}
	for _, key := range keysWithPolicy {
		if _, held := slices.BinarySearch(selectors, key); !held {
			return nil, fmt.Errorf("backup policy %s has no credential in the archive", key)
		}
	}
	return selectors, nil
}

func (a openedArchive) requireSourceRole(role noderole.Role) error {
	if a.manifest.SourceNodeRole != string(role) {
		return authenticatedArchiveError(fmt.Errorf("backup source node role %q cannot be restored into %q", a.manifest.SourceNodeRole, role))
	}
	return nil
}

// loadRestoreSet admits each requested credential for role; none requested
// selects them all. It refuses a request that names a credential admission
// skips, and one that leaves nothing to restore.
func (a openedArchive) loadRestoreSet(requested []string, exportPassphrase []byte, role noderole.Role) (*RestoreSet, error) {
	selected, err := a.selectCredentials(requested)
	if err != nil {
		return nil, err
	}
	set := &RestoreSet{
		SourceNodeRole:   a.manifest.SourceNodeRole,
		ArchiveCreatedAt: a.manifest.CreatedAtUnix,
		Entries:          make([]CredentialEntry, 0, len(selected)),
	}
	set.Skipped, err = a.admitEach(selected, exportPassphrase, role, func(entry CredentialEntry) error {
		set.Entries = append(set.Entries, entry)
		return nil
	})
	if err == nil && ((len(requested) > 0 && len(set.Skipped) > 0) || len(set.Entries) == 0) {
		err = &SkipRefusalError{Skipped: set.Skipped, Named: len(requested) > 0}
	}
	if err != nil {
		set.ZeroSecrets()
		return nil, err
	}
	return set, nil
}

// selectCredentials returns the requested selectors in order, or every
// credential the archive holds when none is requested. A request naming a
// credential twice, or one the archive lacks, is refused.
func (a openedArchive) selectCredentials(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return a.selectors, nil
	}
	selected := slices.Clone(requested)
	slices.Sort(selected)
	for i, selector := range selected {
		if i > 0 && selected[i-1] == selector {
			return nil, fmt.Errorf("duplicate backup selector %q", selector)
		}
		if _, held := slices.BinarySearch(a.selectors, selector); !held {
			return nil, fmt.Errorf("backup has no credential %q", selector)
		}
	}
	return selected, nil
}

// admitEach admits each of selectors for role, in order. It hands every
// admitted entry to admitted, which then owns the entry's secrets, and
// returns the entries it skipped. A member that cannot be read or decrypted
// stops it with an error, and so does an error from admitted.
func (a openedArchive) admitEach(
	selectors []string,
	exportPassphrase []byte,
	role noderole.Role,
	admitted func(CredentialEntry) error,
) ([]SkippedEntry, error) {
	var skipped []SkippedEntry
	for _, selector := range selectors {
		entry, skip, err := a.loadCredentialEntry(selector, exportPassphrase, role)
		if err != nil {
			return nil, withArchivePaths(filepath.Dir(a.keysDir), fmt.Errorf("backup credential %s: %w", selector, err))
		}
		if skip != nil {
			skipped = append(skipped, *skip)
			continue
		}
		if err := admitted(entry); err != nil {
			return nil, err
		}
	}
	return skipped, nil
}

// loadCredentialEntry reads and decrypts one archived credential and its
// archived policy, then admits them. Deep verify, restore, its preview and
// rebuild all load credentials here, so they admit and skip the same ones.
//
// A member that cannot be read or decrypted is an error: the sealed manifest
// holds its digest, so it is damage to the archive, not a credential this
// node cannot use. A decrypted credential or policy this node does not admit
// is returned as skipped, with the reason.
func (a openedArchive) loadCredentialEntry(
	selector string,
	exportPassphrase []byte,
	role noderole.Role,
) (CredentialEntry, *SkippedEntry, error) {
	srcFile := filepath.Join(a.keysDir, selector+".apb")
	// #nosec G304 -- keysDir is the private extracted archive root and selector
	// is one validated archive member basename.
	data, _, err := fsutil.ReadRegularFileLimited(srcFile, crypto.MaxStandaloneEnvelopeBytes)
	if err != nil {
		return CredentialEntry{}, nil, fmt.Errorf("read backup file: %w", err)
	}
	plaintext, err := crypto.DecryptStandalone(data, exportPassphrase)
	if err != nil {
		return CredentialEntry{}, nil, fmt.Errorf("decrypt backup file: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)
	document, err := readBackupPolicy(a.keysDir, selector, exportPassphrase)
	if err != nil {
		return CredentialEntry{}, nil, err
	}
	entry, err := admitCredentialEntry(plaintext, selector, role)
	if err == nil && document != nil {
		if _, err = policy.DecodePolicyV1(document, selector, role); err != nil {
			entry.ZeroSecrets()
			err = fmt.Errorf("backup policy for %s: %w", selector, err)
		}
	}
	if err != nil {
		return CredentialEntry{}, &SkippedEntry{Selector: selector, Reason: err.Error()}, nil
	}
	entry.Policy = document
	entry.StageHint = validatedRotatingHint(entry, a.manifest.RotatingStageHints)
	return entry, nil, nil
}

// admitCredentialEntry parses keyJSON once, checks that it derives selector,
// that role may hold its key type and that this runtime can use it, and
// canonicalizes it. The entry keeps what the parse established, so no later
// step parses the credential again.
func admitCredentialEntry(keyJSON []byte, selector string, role noderole.Role) (CredentialEntry, error) {
	payload, err := keys.ParsePayload(keyJSON)
	if err != nil {
		return CredentialEntry{}, fmt.Errorf("failed to parse backup credential: %w", err)
	}
	// Clearing the secrets on return leaves the entry's payload holding only
	// public facts.
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
	if err := requireRuntimeSupport(payload); err != nil {
		crypto.ZeroBytes(canonical)
		return CredentialEntry{}, err
	}
	return CredentialEntry{credential: &admittedCredential{selector: derived, keyJSON: canonical, payload: payload}}, nil
}

// requireRuntimeSupport refuses a credential this runtime cannot use.
func requireRuntimeSupport(payload *keys.Payload) error {
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
	case keys.CategoryRotatingLsig:
		// ParsePayload already required the family's registered codec to
		// re-derive stage 0 from the seed. The seed is the whole secret; the
		// signer rebuilds its stage address cache from it after a restore.
	default:
		return fmt.Errorf("unsupported managed credential category %q", payload.Category)
	}
	return nil
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
	active storepaths.GenPaths,
	set *RestoreSet,
	kr *crypto.Keyring,
) (RestoreClassification, error) {
	if set == nil || len(set.Entries) == 0 {
		return RestoreClassification{}, fmt.Errorf("restore set is empty")
	}
	if kr == nil {
		return RestoreClassification{}, fmt.Errorf("destination keyring is required")
	}
	role, err := noderole.ParseRole(set.SourceNodeRole)
	if err != nil {
		return RestoreClassification{}, fmt.Errorf("restore set node role: %w", err)
	}
	var result RestoreClassification
	for i := range set.Entries {
		entry := set.Entries[i]
		classifyRestorePolicy(active, role, entry, kr, &result)
		destPath, exists, err := keys.ManagedCredentialDestinationActive(
			active,
			entry.Selector(),
			entry.Category(),
		)
		if err != nil {
			if isManagedClassConflict(err) {
				result.Conflicts = append(result.Conflicts, RestoreConflict{
					Selector: entry.Selector(),
					Category: entry.Category(),
					KeyType:  entry.KeyType(),
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
				Selector:       entry.Selector(),
				Category:       entry.Category(),
				KeyType:        entry.KeyType(),
				ExistingSHA256: fingerprint,
				Reason:         "existing credential is unreadable: " + compareErr.Error(),
			})
			result.Pending = append(result.Pending, entry)
			continue
		}
		equal := bytes.Equal(canonical, entry.keyJSON())
		crypto.ZeroBytes(canonical)
		if equal {
			result.Identical = append(result.Identical, entry)
			continue
		}
		result.Conflicts = append(result.Conflicts, RestoreConflict{
			Selector:       entry.Selector(),
			Category:       entry.Category(),
			KeyType:        entry.KeyType(),
			ExistingSHA256: fingerprint,
			Reason:         "existing credential differs from backup",
		})
		result.Pending = append(result.Pending, entry)
	}
	return result, nil
}

// classifyRestorePolicy decides whether an entry's archived policy is
// installed. A destination without a policy takes the archived one; a
// different destination policy is a conflict that replace_existing resolves;
// a destination policy is kept when the archive carries none.
func classifyRestorePolicy(active storepaths.GenPaths, role noderole.Role, entry CredentialEntry, kr *crypto.Keyring, result *RestoreClassification) {
	if entry.Policy == nil {
		return
	}
	current, err := destinationPolicy(active, role, entry.Selector(), kr)
	switch {
	case err != nil:
		result.Conflicts = append(result.Conflicts, RestoreConflict{
			Selector: entry.Selector(), Category: entry.Category(), KeyType: entry.KeyType(),
			Reason: "existing policy is unreadable: " + err.Error(),
		})
	case current == nil:
	case bytes.Equal(current, entry.Policy):
		return
	default:
		result.Conflicts = append(result.Conflicts, RestoreConflict{
			Selector: entry.Selector(), Category: entry.Category(), KeyType: entry.KeyType(),
			ExistingSHA256: policy.PolicySHA256(current),
			Reason:         "existing policy differs from backup",
		})
	}
	result.Policies = append(result.Policies, entry)
}

func openCanonicalDestination(path string, entry CredentialEntry, kr *crypto.Keyring) ([]byte, error) {
	// #nosec G304 -- path is returned by the managed-credential destination
	// resolver from a validated selector and category, never accepted raw.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ctx, err := keys.CredentialContext(entry.Selector(), entry.Category())
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
	if selector != entry.Selector() || payload.Category != entry.Category() {
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
	active storepaths.GenPaths,
	entry CredentialEntry,
	kr *crypto.Keyring,
	replaceExisting bool,
) error {
	// Only loadCredentialEntry fills an entry, so its selector and category
	// are its payload's. An entry built by hand, or whose credential was
	// cleared through any copy, has nothing to write.
	keyJSON := entry.keyJSON()
	if len(keyJSON) == 0 {
		return fmt.Errorf("restore entry %q holds no admitted credential", entry.Selector())
	}
	selector, category := entry.Selector(), entry.Category()

	destPath, exists, destinationErr := keys.ManagedCredentialDestinationActive(active, selector, category)
	if destinationErr != nil && !isManagedClassConflict(destinationErr) {
		return destinationErr
	}
	if (exists || destinationErr != nil) && !replaceExisting {
		return fmt.Errorf("%w: %s", keys.ErrManagedCredentialExists, selector)
	}
	if destinationErr != nil {
		canonical, err := keys.CanonicalManagedCredentialPathActive(active, selector, category)
		if err != nil {
			return err
		}
		destPath = canonical
		otherExt := keys.AccountKeyExtension
		if filepath.Ext(destPath) == keys.AccountKeyExtension {
			otherExt = keys.CosignerCredentialExtension
		}
		if err := fsutil.RemoveDurable(filepath.Join(active.KeysDir(), selector+otherExt)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove contradictory managed credential: %w", err)
		}
	}

	ctx, err := keys.CredentialContext(selector, category)
	if err != nil {
		return err
	}
	encrypted, err := kr.Seal(keyJSON, ctx)
	if err != nil {
		return fmt.Errorf("encrypt restored credential: %w", err)
	}
	if err := fsutil.MkdirAllPrivate(active.KeysDir()); err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(destPath, encrypted); err != nil {
		return fmt.Errorf("write restored credential: %w", err)
	}
	if category != keys.CategoryWitness {
		_ = fsutil.RemoveDurable(keys.WitnessPublicMetadataPathActive(active, selector))
	}
	if err := keys.WriteWitnessPublicMetadataActive(active, selector, entry.credential.payload); err != nil {
		return fmt.Errorf("write restored witness public metadata: %w", err)
	}
	return nil
}
