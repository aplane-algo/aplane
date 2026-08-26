// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	StoreRootSchema                  = "aplane.store-root.v1"
	StoreRootFormatVersion           = 1
	StoreRootKeyringSchema           = "aplane.keyring.v3"
	StoreRootKeyringEnvelopeVersion  = 3
	StoreRootKeystoreMetadataVersion = 6
	KeystoreLayoutStoreRootV1        = "store-root/v1"
	storeRootKeyringAADDomain        = "aplane.keyring-file.v3"
	storeRootSelectionMACDomain      = "aplane.store-root-selection.v1"
	maxStoreRootBytes                = 2 << 20
	maxStoreRootKeystoreMarkerBytes  = 16 << 10
	storeRootGCMNonceBytes           = 12
	storeRootGCMTagBytes             = 16
)

// StoreRootSelection is the authenticated public projection of the one
// generation/key-authority commit record. It carries no key material.
type StoreRootSelection struct {
	CurrentGenerationID string
	SelectionTerm       int64
}

type storeRootFile struct {
	Schema              string          `json:"schema"`
	FormatVersion       int             `json:"format_version"`
	Keyring             json.RawMessage `json:"keyring"`
	CurrentGenerationID string          `json:"current_generation_id"`
	SelectionTerm       int64           `json:"selection_term"`
	SelectionMAC        string          `json:"selection_mac"`
}

// storeRootKeyringPayload is keyring/v3's sealed shape. The retired pending
// rotation descriptor is deliberately absent: unknown-field rejection makes
// a v2 transition payload invalid rather than silently translating it.
type storeRootKeyringPayload struct {
	Schema            string                       `json:"schema"`
	CurrentTerm       int64                        `json:"current_term"`
	Terms             []sealedTerm                 `json:"terms"`
	HistoricalAnchors []HistoricalGenerationAnchor `json:"historical_anchors"`
}

// SealStoreRoot wraps kr with a fresh passphrase-derived KEK and binds that
// exact wrapped subobject to generationID under the current term. The result
// is canonical compact JSON suitable for one durable replacement.
func SealStoreRoot(
	kr *Keyring,
	passphrase []byte,
	generationID string,
) ([]byte, error) {
	if err := storepaths.ValidateGenerationID(generationID); err != nil {
		return nil, err
	}
	wrapped, err := sealStoreRootKeyring(kr, passphrase)
	if err != nil {
		return nil, err
	}
	return encodeStoreRoot(kr, wrapped, generationID)
}

// OpenStoreRoot strictly parses one canonical root, unwraps its keyring, and
// verifies that the selector is authenticated by exactly that wrapped
// keyring's current term. The caller owns the returned keyring and must Zero
// it when the unlocked session ends.
func OpenStoreRoot(
	encoded []byte,
	passphrase []byte,
) (*Keyring, StoreRootSelection, error) {
	file, err := parseStoreRoot(encoded)
	if err != nil {
		return nil, StoreRootSelection{}, err
	}
	kr, err := openStoreRootKeyring(file.Keyring, passphrase)
	if err != nil {
		return nil, StoreRootSelection{}, err
	}
	success := false
	defer func() {
		if !success {
			kr.Zero()
		}
	}()
	if err := verifyStoreRootSelection(file, kr); err != nil {
		return nil, StoreRootSelection{}, err
	}
	success = true
	return kr, StoreRootSelection{
		CurrentGenerationID: file.CurrentGenerationID,
		SelectionTerm:       file.SelectionTerm,
	}, nil
}

// AuthenticateStoreRoot verifies a fresh exact root read using an already
// open keyring. It does not unwrap or return the wrapped keyring and is the
// confined verification path used by ordinary generation commits that do not
// retain the passphrase-derived KEK.
func AuthenticateStoreRoot(
	encoded []byte,
	kr *Keyring,
) (StoreRootSelection, error) {
	file, err := parseStoreRoot(encoded)
	if err != nil {
		return StoreRootSelection{}, err
	}
	if err := verifyStoreRootSelection(file, kr); err != nil {
		return StoreRootSelection{}, err
	}
	return StoreRootSelection{
		CurrentGenerationID: file.CurrentGenerationID,
		SelectionTerm:       file.SelectionTerm,
	}, nil
}

// ReselectStoreRoot verifies a fresh exact root read with the already-open
// keyring, then returns a canonical candidate selecting generationID. The
// wrapped keyring RawMessage is copied byte-for-byte; ordinary generation
// commits therefore neither need nor retain the passphrase-derived KEK.
func ReselectStoreRoot(
	encoded []byte,
	kr *Keyring,
	generationID string,
) ([]byte, error) {
	if err := storepaths.ValidateGenerationID(generationID); err != nil {
		return nil, err
	}
	file, err := parseStoreRoot(encoded)
	if err != nil {
		return nil, err
	}
	if err := verifyStoreRootSelection(file, kr); err != nil {
		return nil, err
	}
	return encodeStoreRoot(kr, slices.Clone(file.Keyring), generationID)
}

func encodeStoreRoot(
	kr *Keyring,
	wrappedKeyring []byte,
	generationID string,
) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, ErrKeyringNotOpen
	}
	if err := storepaths.ValidateGenerationID(generationID); err != nil {
		return nil, err
	}
	if err := validateStoreRootKeyringHeader(wrappedKeyring); err != nil {
		return nil, err
	}
	selectionMAC, err := storeRootSelectionMAC(
		kr,
		wrappedKeyring,
		generationID,
		kr.currentTerm,
	)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(storeRootFile{
		Schema:              StoreRootSchema,
		FormatVersion:       StoreRootFormatVersion,
		Keyring:             slices.Clone(wrappedKeyring),
		CurrentGenerationID: generationID,
		SelectionTerm:       kr.currentTerm,
		SelectionMAC:        selectionMAC,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal store root: %w", err)
	}
	if len(encoded) > maxStoreRootBytes {
		return nil, fmt.Errorf("store root exceeds size limit %d", maxStoreRootBytes)
	}
	return encoded, nil
}

func parseStoreRoot(encoded []byte) (storeRootFile, error) {
	if len(encoded) > maxStoreRootBytes {
		return storeRootFile{}, fmt.Errorf("store root exceeds size limit %d", maxStoreRootBytes)
	}
	var file storeRootFile
	if err := decodeJSONStrict(encoded, &file); err != nil {
		return storeRootFile{}, fmt.Errorf("parse store root: %w", err)
	}
	if file.Schema != StoreRootSchema {
		return storeRootFile{}, fmt.Errorf("unsupported store root schema %q", file.Schema)
	}
	if file.FormatVersion != StoreRootFormatVersion {
		return storeRootFile{}, fmt.Errorf("unsupported store root format version %d", file.FormatVersion)
	}
	if err := storepaths.ValidateGenerationID(file.CurrentGenerationID); err != nil {
		return storeRootFile{}, err
	}
	if file.SelectionTerm < FirstTerm {
		return storeRootFile{}, fmt.Errorf("invalid store root selection term %d", file.SelectionTerm)
	}
	if err := validateCanonicalSHA256(file.SelectionMAC); err != nil {
		return storeRootFile{}, fmt.Errorf("selection_mac: %w", err)
	}
	if err := validateStoreRootKeyringHeader(file.Keyring); err != nil {
		return storeRootFile{}, err
	}
	canonical, err := json.Marshal(file)
	if err != nil {
		return storeRootFile{}, fmt.Errorf("canonicalize store root: %w", err)
	}
	if !bytes.Equal(encoded, canonical) {
		return storeRootFile{}, fmt.Errorf("store root is not canonical JSON")
	}
	return file, nil
}

func verifyStoreRootSelection(file storeRootFile, kr *Keyring) error {
	if kr == nil || len(kr.terms) == 0 {
		return ErrKeyringNotOpen
	}
	if file.SelectionTerm != kr.currentTerm {
		return fmt.Errorf(
			"store root selection term %d does not equal keyring current term %d",
			file.SelectionTerm,
			kr.currentTerm,
		)
	}
	want, err := storeRootSelectionMAC(
		kr,
		file.Keyring,
		file.CurrentGenerationID,
		file.SelectionTerm,
	)
	if err != nil {
		return err
	}
	wantBytes, _ := hex.DecodeString(want)
	gotBytes, _ := hex.DecodeString(file.SelectionMAC)
	if !hmac.Equal(gotBytes, wantBytes) {
		return fmt.Errorf("store root selection MAC verification failed")
	}
	return nil
}

func storeRootSelectionMAC(
	kr *Keyring,
	wrappedKeyring []byte,
	generationID string,
	selectionTerm int64,
) (string, error) {
	if kr == nil || len(kr.terms) == 0 {
		return "", ErrKeyringNotOpen
	}
	key, ok := kr.terms[selectionTerm]
	if !ok {
		return "", fmt.Errorf("keyring has no key for selection term %d", selectionTerm)
	}
	wrappedDigest := sha256.Sum256(wrappedKeyring)
	var numeric [8]byte
	macInput := appendAADField(nil, []byte(storeRootSelectionMACDomain))
	macInput = appendAADField(macInput, []byte(StoreRootSchema))
	binary.BigEndian.PutUint64(numeric[:], StoreRootFormatVersion)
	macInput = appendAADField(macInput, numeric[:])
	macInput = appendAADField(macInput, []byte(generationID))
	binary.BigEndian.PutUint64(numeric[:], uint64(selectionTerm))
	macInput = appendAADField(macInput, numeric[:])
	macInput = appendAADField(macInput, wrappedDigest[:])
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(macInput)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func sealStoreRootKeyring(kr *Keyring, passphrase []byte) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, ErrKeyringNotOpen
	}
	if kr.rotation != nil {
		return nil, fmt.Errorf("store root keyring v3 does not encode pending rotation state")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("sealing the store root requires a passphrase")
	}
	salt, err := randomBytes(masterSaltLen)
	if err != nil {
		return nil, fmt.Errorf("generate store root keyring salt: %w", err)
	}
	payload := storeRootKeyringPayload{
		Schema:            StoreRootKeyringSchema,
		CurrentTerm:       kr.currentTerm,
		Terms:             payloadFromKeyring(kr).Terms,
		HistoricalAnchors: slices.Clone(kr.historicalAnchors),
	}
	if payload.HistoricalAnchors == nil {
		payload.HistoricalAnchors = []HistoricalGenerationAnchor{}
	}
	if err := validateStoreRootKeyringPayload(&payload); err != nil {
		return nil, fmt.Errorf("invalid store root keyring state: %w", err)
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal store root keyring: %w", err)
	}
	defer ZeroBytes(plaintext)

	kek := deriveMasterKeyParams(passphrase, salt, argon2Time, argon2Memory, argon2Threads)
	defer ZeroBytes(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate store root keyring nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, storeRootKeyringHeaderAAD(
		StoreRootKeyringSchema,
		StoreRootKeyringEnvelopeVersion,
		argon2Time,
		argon2Memory,
		argon2Threads,
		salt,
		nonce,
	))
	return json.Marshal(keyringFile{
		Schema:        StoreRootKeyringSchema,
		EnvelopeVer:   StoreRootKeyringEnvelopeVersion,
		KDFTime:       argon2Time,
		KDFMemory:     argon2Memory,
		KDFThreads:    argon2Threads,
		Salt:          base64.StdEncoding.EncodeToString(salt),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		SealedKeyring: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func openStoreRootKeyring(encoded, passphrase []byte) (*Keyring, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("opening the store root requires a passphrase")
	}
	file, salt, nonce, ciphertext, err := decodeStoreRootKeyringHeader(encoded)
	if err != nil {
		return nil, err
	}
	kek := deriveMasterKeyParams(passphrase, salt, file.KDFTime, file.KDFMemory, file.KDFThreads)
	defer ZeroBytes(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	if err := validateGCMNonce(nonce, gcm); err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, storeRootKeyringHeaderAAD(
		file.Schema,
		file.EnvelopeVer,
		file.KDFTime,
		file.KDFMemory,
		file.KDFThreads,
		salt,
		nonce,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to open store root keyring: %w", err)
	}
	defer ZeroBytes(plaintext)

	var payload storeRootKeyringPayload
	defer func() {
		for i := range payload.Terms {
			ZeroBytes(payload.Terms[i].Key)
		}
	}()
	if err := decodeJSONStrict(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("parse sealed store root keyring: %w", err)
	}
	if keyringDecodeHook != nil {
		keyringDecodeHook(payload.Terms)
	}
	if err := validateStoreRootKeyringPayload(&payload); err != nil {
		return nil, err
	}
	kr := &Keyring{
		terms:             make(map[int64][]byte, len(payload.Terms)),
		currentTerm:       payload.CurrentTerm,
		historicalAnchors: slices.Clone(payload.HistoricalAnchors),
	}
	for i := range payload.Terms {
		term := &payload.Terms[i]
		kr.terms[term.Term] = slices.Clone(term.Key)
	}
	return kr, nil
}

func validateStoreRootKeyringPayload(payload *storeRootKeyringPayload) error {
	return validateKeyringPayloadSchema(&keyringPayload{
		Schema:            payload.Schema,
		CurrentTerm:       payload.CurrentTerm,
		Terms:             payload.Terms,
		HistoricalAnchors: payload.HistoricalAnchors,
	}, StoreRootKeyringSchema)
}

func validateStoreRootKeyringHeader(encoded []byte) error {
	_, _, _, _, err := decodeStoreRootKeyringHeader(encoded)
	return err
}

func decodeStoreRootKeyringHeader(
	encoded []byte,
) (keyringFile, []byte, []byte, []byte, error) {
	if len(encoded) > maxKeyringBytes {
		return keyringFile{}, nil, nil, nil, fmt.Errorf(
			"store root keyring exceeds size limit %d",
			maxKeyringBytes,
		)
	}
	var file keyringFile
	if err := decodeJSONStrict(encoded, &file); err != nil {
		return keyringFile{}, nil, nil, nil, fmt.Errorf("parse store root keyring: %w", err)
	}
	if file.Schema != StoreRootKeyringSchema {
		return keyringFile{}, nil, nil, nil, fmt.Errorf(
			"unsupported store root keyring schema %q",
			file.Schema,
		)
	}
	if file.EnvelopeVer != StoreRootKeyringEnvelopeVersion {
		return keyringFile{}, nil, nil, nil, fmt.Errorf(
			"unsupported store root keyring envelope version %d",
			file.EnvelopeVer,
		)
	}
	if err := checkKDFParams(file.KDFTime, file.KDFMemory, file.KDFThreads); err != nil {
		return keyringFile{}, nil, nil, nil, err
	}
	salt, err := decodeCanonicalBase64("store root keyring salt", file.Salt)
	if err != nil {
		return keyringFile{}, nil, nil, nil, err
	}
	if len(salt) != masterSaltLen {
		return keyringFile{}, nil, nil, nil, fmt.Errorf(
			"store root keyring salt has length %d, want %d",
			len(salt),
			masterSaltLen,
		)
	}
	nonce, err := decodeCanonicalBase64("store root keyring nonce", file.Nonce)
	if err != nil {
		return keyringFile{}, nil, nil, nil, err
	}
	if len(nonce) != storeRootGCMNonceBytes {
		return keyringFile{}, nil, nil, nil, fmt.Errorf(
			"store root keyring nonce has length %d, want %d",
			len(nonce),
			storeRootGCMNonceBytes,
		)
	}
	ciphertext, err := decodeCanonicalBase64("sealed store root keyring", file.SealedKeyring)
	if err != nil {
		return keyringFile{}, nil, nil, nil, err
	}
	if len(ciphertext) < storeRootGCMTagBytes {
		return keyringFile{}, nil, nil, nil, fmt.Errorf("sealed store root keyring is too short")
	}
	canonical, err := json.Marshal(file)
	if err != nil {
		return keyringFile{}, nil, nil, nil, err
	}
	if !bytes.Equal(encoded, canonical) {
		return keyringFile{}, nil, nil, nil, fmt.Errorf("store root keyring is not canonical JSON")
	}
	return file, salt, nonce, ciphertext, nil
}

func storeRootKeyringHeaderAAD(
	schema string,
	version int,
	kdfTime, kdfMemory uint32,
	kdfThreads uint8,
	salt, nonce []byte,
) []byte {
	var out []byte
	out = appendAADField(out, []byte(storeRootKeyringAADDomain))
	out = appendAADField(out, []byte(schema))
	var numeric [8]byte
	binary.BigEndian.PutUint64(numeric[:], uint64(version))
	out = appendAADField(out, numeric[:])
	binary.BigEndian.PutUint64(numeric[:], uint64(kdfTime))
	out = appendAADField(out, numeric[:])
	binary.BigEndian.PutUint64(numeric[:], uint64(kdfMemory))
	out = appendAADField(out, numeric[:])
	binary.BigEndian.PutUint64(numeric[:], uint64(kdfThreads))
	out = appendAADField(out, numeric[:])
	out = appendAADField(out, salt)
	out = appendAADField(out, nonce)
	return out
}

// ReadStoreRootExact checks the hard layout gate and returns one bounded,
// regular-file read for callers that already hold the store mutation lock.
func ReadStoreRootExact(keystoreDir string) ([]byte, error) {
	if err := checkStoreRootMarker(keystoreDir); err != nil {
		return nil, err
	}
	encoded, _, err := fsutil.ReadRegularFileLimited(
		filepath.Join(keystoreDir, storepaths.StoreRootName),
		maxStoreRootBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("read store root: %w", err)
	}
	return encoded, nil
}

func OpenStoreRootStore(
	keystoreDir string,
	passphrase []byte,
) (*Keyring, StoreRootSelection, error) {
	encoded, err := ReadStoreRootExact(keystoreDir)
	if err != nil {
		return nil, StoreRootSelection{}, err
	}
	return OpenStoreRoot(encoded, passphrase)
}

func StoreRootExistsIn(keystoreDir string) bool {
	info, err := os.Lstat(filepath.Join(keystoreDir, storepaths.StoreRootName))
	return err == nil && info.Mode().IsRegular()
}

func writeStoreRootMarker(keystoreDir string) error {
	data, err := json.MarshalIndent(keyringMarker{
		Version: StoreRootKeystoreMetadataVersion,
		Layout:  KeystoreLayoutStoreRootV1,
		Created: time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileDurable(filepath.Join(keystoreDir, keystoreMetaFile), data); err != nil {
		return fmt.Errorf("write store root marker: %w", err)
	}
	return nil
}

// InitializeStoreRootMarker writes the hard v6/store-root-v1 layout gate. A
// supported existing marker is an idempotent crash retry; every other marker
// is rejected and never translated.
func InitializeStoreRootMarker(keystoreDir string) error {
	markerPath := filepath.Join(keystoreDir, keystoreMetaFile)
	if _, err := os.Lstat(markerPath); err == nil {
		return checkStoreRootMarker(keystoreDir)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := fsutil.MkdirAllPrivate(keystoreDir); err != nil {
		return err
	}
	return writeStoreRootMarker(keystoreDir)
}

func checkStoreRootMarker(keystoreDir string) error {
	data, _, err := fsutil.ReadRegularFileLimited(
		filepath.Join(keystoreDir, keystoreMetaFile),
		maxStoreRootKeystoreMarkerBytes,
	)
	if err != nil {
		return fmt.Errorf("read store root marker: %w", err)
	}
	var marker keyringMarker
	if err := decodeJSONStrict(data, &marker); err != nil {
		return fmt.Errorf("parse store root marker: %w", err)
	}
	if marker.Version != StoreRootKeystoreMetadataVersion ||
		marker.Layout != KeystoreLayoutStoreRootV1 {
		return fmt.Errorf(
			"unsupported keystore marker version %d layout %q: this release requires version %d layout %q; restore credentials into a freshly initialized store",
			marker.Version,
			marker.Layout,
			StoreRootKeystoreMetadataVersion,
			KeystoreLayoutStoreRootV1,
		)
	}
	created, err := time.Parse(time.RFC3339, marker.Created)
	if err != nil || created.UTC().Format(time.RFC3339) != marker.Created {
		return fmt.Errorf("store root marker has invalid created timestamp %q", marker.Created)
	}
	return nil
}
