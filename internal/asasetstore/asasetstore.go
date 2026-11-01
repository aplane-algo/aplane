// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package asasetstore reads and writes a generation's ASA set: the
// asa_set.json authority file and its .hmac sidecar, authenticated under the
// keyring's own ASA-set integrity domain, so a sidecar for any other
// authority file cannot authenticate it.
//
// A generation with neither file has the built-in assets only. Anything else
// short of a valid, authenticated set (a file without its sidecar, a sidecar
// without its file, a bad MAC, or bytes that do not parse) is an integrity
// failure, never an empty set.
package asasetstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/asaset"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/integritysidecar"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// IntegrityKeyID names the sidecar's key derivation.
const IntegrityKeyID = "keystore-master-hkdf-asa-set-v1"

// maxFileBytes bounds the set file read: thousands of confirmations.
const maxFileBytes = 1 << 20

var (
	ErrIntegrity      = errors.New("asa set integrity check failed")
	ErrMissingFile    = errors.New("asa set file missing")
	ErrUnreadable     = errors.New("asa set file unreadable")
	ErrInvalid        = errors.New("asa set file invalid")
	ErrMissingSidecar = errors.New("asa set integrity sidecar missing")
	ErrBadSidecar     = errors.New("asa set integrity sidecar invalid")
	ErrUnsupported    = errors.New("asa set integrity sidecar unsupported")
	ErrMismatch       = errors.New("asa set integrity mismatch")
)

var sidecarSpec = integritysidecar.Spec{
	Domain: apcrypto.IntegrityDomainASASet,
	KeyID:  IntegrityKeyID,
	Name:   "asa set",
	Errors: integritysidecar.Errors{
		Check:       ErrIntegrity,
		Bad:         ErrBadSidecar,
		Missing:     ErrMissingSidecar,
		Unsupported: ErrUnsupported,
		Mismatch:    ErrMismatch,
	},
}

// sidecar authenticates the set file. Fields beyond the embedded security
// header are diagnostic.
type sidecar struct {
	integritysidecar.Header
	SetSHA256    string `json:"asa_set_sha256,omitempty"`
	SignedAtUnix int64  `json:"signed_at_unix,omitempty"`
}

// Load reads and authenticates the ASA set in one already-resolved
// generation. A generation with neither file has an empty set.
func Load(active storepaths.ActivePaths, kr *apcrypto.Keyring) (*asaset.Set, error) {
	path, sidecarPath := active.ASASetPath(), active.ASASetIntegritySidecar()
	fileExists, err := exists(path)
	if err != nil {
		return nil, integrityWrap(ErrUnreadable, err, "cannot stat %s", path)
	}
	sidecarExists, err := exists(sidecarPath)
	if err != nil {
		return nil, integrityWrap(ErrBadSidecar, err, "cannot stat %s", sidecarPath)
	}
	switch {
	case !fileExists && !sidecarExists:
		return asaset.Empty(), nil
	case !fileExists:
		return nil, integrityError(ErrMissingFile, "%s has no asa set file", sidecarPath)
	}
	data, _, err := fsutil.ReadRegularFileLimited(path, maxFileBytes+1)
	if err != nil {
		return nil, integrityWrap(ErrUnreadable, err, "cannot read %s", path)
	}
	if len(data) > maxFileBytes {
		return nil, integrityError(ErrInvalid, "%s exceeds %d bytes", path, maxFileBytes)
	}
	var sc sidecar
	if err := sidecarSpec.Load(sidecarPath, &sc); err != nil {
		return nil, err
	}
	if err := sidecarSpec.Verify(data, &sc.Header, kr); err != nil {
		return nil, err
	}
	set, err := asaset.Parse(data)
	if err != nil {
		return nil, integrityWrap(ErrInvalid, err, "%s", path)
	}
	return set, nil
}

// Write stores set and its sidecar in one generation being built. The two
// files are written as one durable set.
func Write(active storepaths.ActivePaths, set *asaset.Set, kr *apcrypto.Keyring, signedAt time.Time) error {
	data, err := set.Marshal()
	if err != nil {
		return err
	}
	sidecarBytes, err := signSidecar(data, kr, signedAt)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileSetDurable(
		fsutil.DurableFileWrite{Path: active.ASASetPath(), Data: data, Profile: fsutil.PrivateStoreFileProfile},
		fsutil.DurableFileWrite{Path: active.ASASetIntegritySidecar(), Data: sidecarBytes, Profile: fsutil.PrivateStoreFileProfile},
	); err != nil {
		return fmt.Errorf("write asa set: %w", err)
	}
	return nil
}

// Resign authenticates the set file's exact bytes with kr: what passphrase
// rotation needs, which re-keys every authority file without changing it.
// The bytes must already verify under oldKeyring.
func Resign(data, sidecarBytes []byte, oldKeyring, kr *apcrypto.Keyring, signedAt time.Time) ([]byte, error) {
	var sc sidecar
	if err := sidecarSpec.Parse(sidecarBytes, &sc); err != nil {
		return nil, err
	}
	if err := sidecarSpec.Verify(data, &sc.Header, oldKeyring); err != nil {
		return nil, err
	}
	if _, err := asaset.Parse(data); err != nil {
		return nil, integrityWrap(ErrInvalid, err, "asa set")
	}
	return signSidecar(data, kr, signedAt)
}

func signSidecar(data []byte, kr *apcrypto.Keyring, signedAt time.Time) ([]byte, error) {
	header, err := sidecarSpec.Sign(data, kr)
	if err != nil {
		return nil, err
	}
	if signedAt.IsZero() {
		signedAt = time.Now()
	}
	sum := sha256.Sum256(data)
	return sidecarSpec.Marshal(&sidecar{Header: header, SetSHA256: hex.EncodeToString(sum[:]), SignedAtUnix: signedAt.UTC().Unix()})
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

func integrityError(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrIntegrity, kind, fmt.Sprintf(format, args...))
}

func integrityWrap(kind, cause error, format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s: %w", ErrIntegrity, kind, fmt.Sprintf(format, args...), cause)
}
