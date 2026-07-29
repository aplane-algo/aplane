// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	KeyringKeystoreMetadataVersion = 4

	// KeystoreLayoutKeyringV1 is the layout tag recorded in version-4
	// metadata.
	KeystoreLayoutKeyringV1 = "keyring/v1"
)

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
	if err := fsutil.MkdirAll(keystoreDir); err != nil {
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

// OpenKeyringStore checks the version gate and opens the root with
// passphrase. A successful unwrap is the passphrase check.
func OpenKeyringStore(keystoreDir string, passphrase []byte) (*Keyring, error) {
	if err := checkKeyringMarker(keystoreDir); err != nil {
		return nil, err
	}
	encoded, err := os.ReadFile(KeyringPath(keystoreDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"keystore not initialized (missing %s in %s)",
				KeyringFileName, keystoreDir,
			)
		}
		return nil, fmt.Errorf("failed to read keyring: %w", err)
	}
	return OpenKeyring(encoded, passphrase)
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
		Layout:  KeystoreLayoutKeyringV1,
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
	if err := json.Unmarshal(data, &marker); err != nil {
		return fmt.Errorf("failed to parse keystore marker: %w", err)
	}
	if marker.Version != KeyringKeystoreMetadataVersion {
		return fmt.Errorf(
			"unsupported keystore metadata version %d: this release only reads stores it initialized (version %d); restore from a backup archive into a fresh store",
			marker.Version, KeyringKeystoreMetadataVersion,
		)
	}
	if marker.Layout != KeystoreLayoutKeyringV1 {
		return fmt.Errorf(
			"keystore metadata version %d has unsupported layout %q",
			marker.Version, marker.Layout,
		)
	}
	return nil
}
