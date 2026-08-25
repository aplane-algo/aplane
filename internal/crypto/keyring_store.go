// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// A keyring store keeps its secrets in one place. keyring.enc is the
// cryptographic root — KDF parameters, salt, and the sealed term set — and
// .keystore is reduced to a static marker recording the format version and
// layout so an older binary refuses the store before touching anything.
const (
	// KeyringFileName is the store's cryptographic root, beside .keystore in
	// the identity metadata directory.
	KeyringFileName = "keyring.enc"

	// KeyringKeystoreMetadataVersion marks a store whose keys live in a
	// keyring. Older binaries reject it at the version gate, exactly as
	// pre-generation binaries reject version 3.
	KeyringKeystoreMetadataVersion = 5

	// KeystoreLayoutKeyringV2 is the layout tag recorded in version-5
	// metadata.
	KeystoreLayoutKeyringV2 = "keyring/v2"
)

var (
	// ErrKeyringNotOpen prevents nil receivers from being mistaken for a
	// settled authority by guards used at signing and mutation boundaries.
	ErrKeyringNotOpen = errors.New("keyring is not open")

	// ErrRotationPending prevents ordinary signing and mutation from using a
	// root that only the explicit resume path may advance.
	ErrRotationPending = errors.New("keyring rotation is pending")

	// ErrRotationAlreadyPending is the R5 guard: a pending root can only be
	// resumed, never appended again.
	ErrRotationAlreadyPending = fmt.Errorf(
		"%w: cannot append another term",
		ErrRotationPending,
	)

	// ErrNoRotationPending reports that completion was requested for a root
	// with no transition descriptor.
	ErrNoRotationPending = errors.New("no keyring rotation is pending")

	// ErrRotationCommitDurabilityUnknown means the exact new root is visible
	// after an error syncing its directory. The in-memory keyring adopts the
	// visible pending or settled state, but the caller must enter recovery
	// until durability is reconciled.
	ErrRotationCommitDurabilityUnknown = errors.New("rotation root commit durability is unknown")

	// ErrRotationCommitStateUnknown means root publication could not be
	// classified after a durable-write failure. The caller must reopen the
	// store and must not retry a transition write with stale in-memory state.
	ErrRotationCommitStateUnknown = errors.New("rotation root commit state is unknown")
)

// RotationSnapshotWriter durably publishes a snapshot sealed by target and
// returns the exact reference to carry in the pending root.
type RotationSnapshotWriter func(
	target *Keyring,
	fromTerm, toTerm int64,
) (RotationSnapshotReference, error)

// KeyringPath returns the keyring root's path within a metadata directory.
func KeyringPath(keystoreDir string) string {
	return filepath.Join(keystoreDir, KeyringFileName)
}

// KeyringExistsIn reports whether a keyring store has been initialized.
func KeyringExistsIn(keystoreDir string) bool {
	info, err := os.Lstat(KeyringPath(keystoreDir))
	return err == nil && info.Mode().IsRegular()
}

// CreateKeyringStore initializes a new keyring store: a fresh term 1, the
// sealed root, and the version marker.
//
// The marker is written first and the root second, so a crash between them
// leaves a store that is recognizably uninitialized (marker without a root)
// rather than one whose root exists but whose version is unknown.
func CreateKeyringStore(keystoreDir string, passphrase []byte) (*Keyring, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("initializing a keyring store requires a passphrase")
	}
	if KeyringExistsIn(keystoreDir) {
		return nil, fmt.Errorf("keyring already exists in %s", keystoreDir)
	}
	if err := fsutil.MkdirAllPrivate(keystoreDir); err != nil {
		return nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}

	kr, err := NewKeyring()
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			kr.Zero()
		}
	}()

	if err := writeKeyringMarker(keystoreDir); err != nil {
		return nil, err
	}
	if err := WriteKeyring(keystoreDir, kr, passphrase); err != nil {
		return nil, err
	}
	success = true
	return kr, nil
}

// WriteKeyring seals the keyring under passphrase and durably replaces the
// root. This is the whole of a passphrase change: one atomic file write,
// with no second record that must agree with it.
func WriteKeyring(keystoreDir string, kr *Keyring, passphrase []byte) error {
	encoded, err := SealKeyring(kr, passphrase)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(KeyringPath(keystoreDir), encoded); err != nil {
		return fmt.Errorf("failed to write keyring: %w", err)
	}
	return nil
}

// StartRotation atomically publishes the root transition after its target-
// term snapshot is durable. It installs the R5 guard, appends exactly one
// term, promotes it, records the former current term as retiring, and adopts
// the visible pending state into kr.
//
// The caller holds the store mutation lock. writeSnapshot must use target
// only to seal and durably publish the cutover snapshot; the root is written
// only after it returns a valid exact-file reference.
func StartRotation(
	keystoreDir string,
	kr *Keyring,
	passphrase []byte,
	anchors []HistoricalGenerationAnchor,
	writeSnapshot RotationSnapshotWriter,
) error {
	if kr == nil || len(kr.terms) == 0 {
		return fmt.Errorf("start rotation: keyring is not open")
	}
	if len(passphrase) == 0 {
		return fmt.Errorf("start rotation: passphrase is required")
	}
	if writeSnapshot == nil {
		return fmt.Errorf("start rotation: snapshot writer is required")
	}
	if anchors == nil {
		return fmt.Errorf("start rotation: historical anchors must be an array")
	}
	if kr.rotation != nil {
		return ErrRotationAlreadyPending
	}
	if kr.currentTerm == math.MaxInt64 {
		return fmt.Errorf("start rotation: current term is exhausted")
	}
	if err := checkKeyringMarker(keystoreDir); err != nil {
		return err
	}

	candidate, err := cloneKeyring(kr)
	if err != nil {
		return fmt.Errorf("start rotation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			candidate.Zero()
		}
	}()

	fromTerm := candidate.currentTerm
	toTerm := fromTerm + 1
	targetKey, err := randomBytes(argon2KeyLen)
	if err != nil {
		return fmt.Errorf("start rotation: generate target term: %w", err)
	}
	candidate.terms[toTerm] = targetKey
	candidate.currentTerm = toTerm
	candidate.historicalAnchors = slices.Clone(anchors)
	payload := payloadFromKeyring(candidate)
	if err := validateKeyringPayload(&payload); err != nil {
		return fmt.Errorf("start rotation candidate: %w", err)
	}
	if err := requirePreservedHistoricalAnchors(kr.historicalAnchors, anchors); err != nil {
		return fmt.Errorf("start rotation: %w", err)
	}

	ref, err := writeSnapshot(candidate, fromTerm, toTerm)
	if err != nil {
		return fmt.Errorf("start rotation snapshot: %w", err)
	}
	if err := ref.Validate(); err != nil {
		return fmt.Errorf("start rotation snapshot reference: %w", err)
	}
	candidate.rotation = &rotationDescriptor{
		FromTerm:       fromTerm,
		SnapshotSHA256: ref.SHA256,
		SnapshotSize:   ref.Size,
	}
	encoded, err := SealKeyring(candidate, passphrase)
	if err != nil {
		return fmt.Errorf("start rotation root: %w", err)
	}
	rootPath := KeyringPath(keystoreDir)
	if err := fsutil.WriteFileDurable(rootPath, encoded); err != nil {
		onDisk, readErr := readKeyringFile(rootPath)
		switch {
		case readErr == nil && bytes.Equal(onDisk, encoded):
			adoptKeyring(kr, candidate)
			committed = true
			return fmt.Errorf("%w: %w", ErrRotationCommitDurabilityUnknown, err)
		case readErr != nil:
			return fmt.Errorf(
				"%w: write error: %v; classify visible root: %v",
				ErrRotationCommitStateUnknown,
				err,
				readErr,
			)
		default:
			return fmt.Errorf("start rotation root commit: %w", err)
		}
	}
	adoptKeyring(kr, candidate)
	committed = true
	return nil
}

// CloseRotation atomically clears the pending descriptor after the caller has
// verified every snapshot-pinned output and durably published any required
// completion baseline. It preserves every resident term and historical
// generation anchor; only current-state authority changes from
// {current, from} back to {current}.
//
// The caller holds the store mutation lock. The referenced snapshot must
// remain present until this function succeeds.
func CloseRotation(
	keystoreDir string,
	kr *Keyring,
	passphrase []byte,
) error {
	if kr == nil || len(kr.terms) == 0 {
		return fmt.Errorf("close rotation: keyring is not open")
	}
	if len(passphrase) == 0 {
		return fmt.Errorf("close rotation: passphrase is required")
	}
	if kr.rotation == nil {
		return ErrNoRotationPending
	}
	if err := checkKeyringMarker(keystoreDir); err != nil {
		return err
	}

	candidate, err := cloneKeyring(kr)
	if err != nil {
		return fmt.Errorf("close rotation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			candidate.Zero()
		}
	}()

	candidate.rotation = nil
	payload := payloadFromKeyring(candidate)
	if err := validateKeyringPayload(&payload); err != nil {
		return fmt.Errorf("close rotation candidate: %w", err)
	}
	encoded, err := SealKeyring(candidate, passphrase)
	if err != nil {
		return fmt.Errorf("close rotation root: %w", err)
	}
	rootPath := KeyringPath(keystoreDir)
	if err := fsutil.WriteFileDurable(rootPath, encoded); err != nil {
		onDisk, readErr := readKeyringFile(rootPath)
		switch {
		case readErr == nil && bytes.Equal(onDisk, encoded):
			adoptKeyring(kr, candidate)
			committed = true
			return fmt.Errorf("%w: %w", ErrRotationCommitDurabilityUnknown, err)
		case readErr != nil:
			return fmt.Errorf(
				"%w: write error: %v; classify visible root: %v",
				ErrRotationCommitStateUnknown,
				err,
				readErr,
			)
		default:
			return fmt.Errorf("close rotation root commit: %w", err)
		}
	}
	adoptKeyring(kr, candidate)
	committed = true
	return nil
}

// OpenKeyringStore checks the version gate and opens the root with
// passphrase. A successful unwrap is the passphrase check.
func OpenKeyringStore(keystoreDir string, passphrase []byte) (*Keyring, error) {
	if err := checkKeyringMarker(keystoreDir); err != nil {
		return nil, err
	}
	encoded, err := readKeyringFile(KeyringPath(keystoreDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"keystore not initialized (missing %s in %s)",
				KeyringFileName, keystoreDir,
			)
		}
		return nil, err
	}
	return OpenKeyring(encoded, passphrase)
}

func cloneKeyring(kr *Keyring) (*Keyring, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, fmt.Errorf("keyring is not open")
	}
	cloned := &Keyring{
		terms:             make(map[int64][]byte, len(kr.terms)),
		currentTerm:       kr.currentTerm,
		historicalAnchors: slices.Clone(kr.historicalAnchors),
		rotation:          cloneRotationDescriptor(kr.rotation),
	}
	for term, key := range kr.terms {
		cloned.terms[term] = slices.Clone(key)
	}
	return cloned, nil
}

func adoptKeyring(dst, src *Keyring) {
	for term, key := range dst.terms {
		ZeroBytes(key)
		delete(dst.terms, term)
	}
	dst.terms = src.terms
	dst.currentTerm = src.currentTerm
	dst.historicalAnchors = src.historicalAnchors
	dst.rotation = src.rotation
	src.terms = nil
	src.currentTerm = 0
	src.historicalAnchors = nil
	src.rotation = nil
}

func requirePreservedHistoricalAnchors(
	existing, replacement []HistoricalGenerationAnchor,
) error {
	for _, anchor := range existing {
		index, found := slices.BinarySearchFunc(
			replacement,
			anchor.GenerationID,
			func(candidate HistoricalGenerationAnchor, generationID string) int {
				return strings.Compare(candidate.GenerationID, generationID)
			},
		)
		if !found || replacement[index] != anchor {
			return fmt.Errorf(
				"historical anchor for generation %s would be dropped or changed",
				anchor.GenerationID,
			)
		}
	}
	return nil
}

// readKeyringFile reads the root, refusing anything that is not a regular
// file and stopping at the size limit rather than after it. os.ReadFile would
// follow a symlink to a device or pull an oversized file entirely into memory
// before the limit could reject it.
func readKeyringFile(path string) ([]byte, error) {
	encoded, _, err := fsutil.ReadRegularFileLimited(path, maxKeyringBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyring: %w", err)
	}
	return encoded, nil
}

// VerifyPassphraseWithKeyring checks a passphrase without retaining the
// keyring. The unwrap is the check, so the term keys it produces are zeroed
// immediately rather than returned.
func VerifyPassphraseWithKeyring(passphrase []byte, keystoreDir string) error {
	kr, err := OpenKeyringStore(keystoreDir, passphrase)
	if err != nil {
		return err
	}
	kr.Zero()
	return nil
}

// keyringMarker is the static .keystore content for a keyring store. It
// carries no salt, no verifier, and no KDF parameters: those live in the
// root, so nothing here can disagree with it.
type keyringMarker struct {
	Version int    `json:"version"`
	Layout  string `json:"layout"`
	Created string `json:"created"`
}

func writeKeyringMarker(keystoreDir string) error {
	data, err := json.MarshalIndent(keyringMarker{
		Version: KeyringKeystoreMetadataVersion,
		Layout:  KeystoreLayoutKeyringV2,
		Created: time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keystore marker: %w", err)
	}
	if err := fsutil.WriteFileDurable(filepath.Join(keystoreDir, keystoreMetaFile), data); err != nil {
		return fmt.Errorf("failed to write keystore marker: %w", err)
	}
	return nil
}

func checkKeyringMarker(keystoreDir string) error {
	data, err := os.ReadFile(filepath.Join(keystoreDir, keystoreMetaFile))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf(
				"keystore not initialized (missing %s in %s)",
				keystoreMetaFile, keystoreDir,
			)
		}
		return fmt.Errorf("failed to read keystore marker: %w", err)
	}
	var marker keyringMarker
	if err := decodeJSONStrict(data, &marker); err != nil {
		return fmt.Errorf("failed to parse keystore marker: %w", err)
	}
	if marker.Version != KeyringKeystoreMetadataVersion {
		return fmt.Errorf(
			"unsupported keystore metadata version %d: this release only reads stores it initialized (version %d); restore from a backup archive into a fresh store",
			marker.Version, KeyringKeystoreMetadataVersion,
		)
	}
	if marker.Layout != KeystoreLayoutKeyringV2 {
		return fmt.Errorf(
			"keystore metadata version %d has unsupported layout %q",
			marker.Version, marker.Layout,
		)
	}
	created, err := time.Parse(time.RFC3339, marker.Created)
	if err != nil || created.UTC().Format(time.RFC3339) != marker.Created {
		return fmt.Errorf("keystore marker has invalid created timestamp %q", marker.Created)
	}
	return nil
}
