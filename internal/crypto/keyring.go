// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// The keyring is the store's single cryptographic root
// (docs/PROPOSAL_KEYTERM_ROTATION.md). It is self-contained: it carries its
// own KDF parameters and salt in the clear and an AEAD-sealed set of key
// terms. Successful unwrap is the passphrase check, so no separate verifier
// exists and a passphrase change is one atomic file write.
//
// This release writes the phase-3 payload shape but still accepts exactly one
// term. Term append and the rewrap window remain disabled until their
// authority checks and R5 guard can land in the same change.
const (
	// KeyringSchema identifies the sealed keyring payload.
	KeyringSchema = "aplane.keyring.v2"
	// KeyringFileVersion is the on-disk envelope version for keyring.enc.
	KeyringFileVersion = 2

	// keyringAADDomain separates the root file's header binding from the term
	// envelope's, so neither construction's bytes can be replayed as the
	// other's.
	keyringAADDomain = "aplane.keyring-file.v2"

	// FirstTerm is the term every store is initialized with.
	FirstTerm = 1

	maxKeyringBytes          = 1 << 20
	maxRotationSnapshotBytes = 16 << 20
)

// keyringFile is the on-disk shape of keyring.enc. The KDF parameters and
// salt are plaintext because they are needed to derive the KEK that opens
// the ciphertext; everything secret lives inside the sealed payload.
type keyringFile struct {
	Schema        string `json:"schema"`
	EnvelopeVer   int    `json:"envelope_version"`
	KDFTime       uint32 `json:"kdf_time"`
	KDFMemory     uint32 `json:"kdf_memory"`
	KDFThreads    uint8  `json:"kdf_threads"`
	Salt          string `json:"salt"`
	Nonce         string `json:"nonce"`
	SealedKeyring string `json:"sealed_keyring"`
}

// keyringPayload is the sealed plaintext.
type keyringPayload struct {
	Schema            string              `json:"schema"`
	CurrentTerm       int64               `json:"current_term"`
	Terms             []sealedTerm        `json:"terms"`
	HistoricalAnchors []historicalAnchor  `json:"historical_anchors"`
	Rotation          *rotationDescriptor `json:"rotation,omitempty"`
}

type sealedTerm struct {
	Term int64  `json:"term"`
	Key  []byte `json:"key"`
}

type historicalAnchor struct {
	GenerationID string `json:"generation_id"`
	SealSize     int64  `json:"seal_size"`
	SealSHA256   string `json:"seal_sha256"`
}

type rotationDescriptor struct {
	FromTerm       int64  `json:"from_term"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	SnapshotSize   int64  `json:"snapshot_size"`
}

// Key is []byte rather than a base64 string so the decoder writes term key
// material into a slice that can be zeroed. A string would be immutable and
// would survive Zero until the collector ran.
//
// The residual is the encoder's own scratch buffers on the seal path, which
// json.Marshal owns and does not expose. Removing that too means a
// hand-rolled binary payload, which is worth doing when the payload grows
// past one term.

// Keyring holds the store's term keys for the duration of an unlocked
// session. It deliberately exposes operations rather than key material:
// callers seal and open, and never hold a key they could use with the wrong
// term or forget to zero.
type Keyring struct {
	terms       map[int64][]byte
	currentTerm int64
}

// NewKeyring creates a keyring holding one freshly generated term.
func NewKeyring() (*Keyring, error) {
	key, err := randomBytes(argon2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("generate term key: %w", err)
	}
	return &Keyring{
		terms:       map[int64][]byte{FirstTerm: key},
		currentTerm: FirstTerm,
	}, nil
}

// NewKeyringFromKey adopts an existing key as the first term.
//
// It exists for test fixtures that hold a known key. Production code opens a
// keyring rather than constructing one, and an architecture test enforces
// that: this is the one remaining way to place arbitrary bytes behind the
// keyring API, so using it in production would undo the confinement that keeps
// passphrase derivation inside this package.
func NewKeyringFromKey(key []byte) (*Keyring, error) {
	if len(key) != argon2KeyLen {
		return nil, fmt.Errorf("term key must be %d bytes, got %d", argon2KeyLen, len(key))
	}
	return &Keyring{
		terms:       map[int64][]byte{FirstTerm: slices.Clone(key)},
		currentTerm: FirstTerm,
	}, nil
}

// CurrentTerm returns the term new writes use.
func (kr *Keyring) CurrentTerm() int64 { return kr.currentTerm }

// Zero clears every term key. Callers must call it when locking.
func (kr *Keyring) Zero() {
	if kr == nil {
		return
	}
	for term, key := range kr.terms {
		ZeroBytes(key)
		delete(kr.terms, term)
	}
	kr.currentTerm = 0
}

// Seal encrypts plaintext under the current term, binding the object's
// logical identity into the envelope's authenticated data.
func (kr *Keyring) Seal(plaintext []byte, ctx ObjectContext) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, fmt.Errorf("keyring is not open")
	}
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	key, ok := kr.terms[kr.currentTerm]
	if !ok {
		return nil, fmt.Errorf("keyring has no key for current term %d", kr.currentTerm)
	}
	return sealUnderTerm(plaintext, key, kr.currentTerm, ctx)
}

// Open decrypts an envelope, selecting the term the envelope names and
// verifying the object context it was sealed with.
//
// This release holds one term, so "the term the envelope names" is always the
// current one. The lookup is written term-generally because the next phase-3
// slice adds retiring terms, but the decoder below keeps multi-term roots
// disabled until Open can enforce the transition's authority set.
func (kr *Keyring) Open(sealed []byte, ctx ObjectContext) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, fmt.Errorf("keyring is not open")
	}
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	term, err := envelopeTerm(sealed)
	if err != nil {
		return nil, err
	}
	key, ok := kr.terms[term]
	if !ok {
		return nil, fmt.Errorf("keyring has no key for term %d", term)
	}
	return openUnderTerm(sealed, key, term, ctx)
}

// PolicyIntegrityKey derives the identity's policy-integrity HMAC key from
// the current term. The caller owns the returned key and should zero it.
func (kr *Keyring) PolicyIntegrityKey() ([]byte, error) {
	return kr.IntegrityKey([]byte(policyIntegrityHKDFInfo), PolicyIntegrityKeyLength)
}

// NodeRoleIntegrityKey derives the identity's node-role HMAC key from the
// current term. The caller owns the returned key and should zero it.
func (kr *Keyring) NodeRoleIntegrityKey() ([]byte, error) {
	return kr.IntegrityKey([]byte(nodeRoleIntegrityHKDFInfo), NodeRoleIntegrityKeyLength)
}

// IntegrityKey derives the HMAC key for one integrity domain from the
// current term. It returns key material because the HMAC construction lives
// in callers today; phase 3 replaces it with SignIntegrity/VerifyIntegrity
// so that material stops leaving this package.
//
// It shares deriveIntegrityKey with the domain helpers above, which is what
// keeps every sidecar already on disk verifiable: the HKDF inputs are
// (term key, info), and adding a salt or a domain string here would silently
// invalidate all of them.
func (kr *Keyring) IntegrityKey(info []byte, length int) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, fmt.Errorf("keyring is not open")
	}
	key, ok := kr.terms[kr.currentTerm]
	if !ok {
		return nil, fmt.Errorf("keyring has no key for current term %d", kr.currentTerm)
	}
	return deriveIntegrityKey(key, info, length, "keyring")
}

// ----------------------------------------------------------------------------
// keyring.enc

// SealKeyring wraps the keyring under a KEK derived from passphrase and
// returns the complete keyring.enc bytes. The salt is fresh on every call,
// so a passphrase change rewrites exactly this one file.
func SealKeyring(kr *Keyring, passphrase []byte) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, fmt.Errorf("keyring is not open")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("sealing the keyring requires a passphrase")
	}
	salt, err := randomBytes(masterSaltLen)
	if err != nil {
		return nil, fmt.Errorf("generate keyring salt: %w", err)
	}

	terms := make([]sealedTerm, 0, len(kr.terms))
	for _, term := range kr.sortedTerms() {
		terms = append(terms, sealedTerm{Term: term, Key: kr.terms[term]})
	}
	payload := keyringPayload{
		Schema:            KeyringSchema,
		CurrentTerm:       kr.currentTerm,
		Terms:             terms,
		HistoricalAnchors: []historicalAnchor{},
	}
	if err := validateKeyringPayload(&payload); err != nil {
		return nil, fmt.Errorf("invalid keyring state: %w", err)
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal keyring: %w", err)
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
		return nil, fmt.Errorf("generate keyring nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, keyringHeaderAAD(
		KeyringSchema, KeyringFileVersion,
		argon2Time, argon2Memory, argon2Threads, salt, nonce,
	))

	encoded, err := json.MarshalIndent(keyringFile{
		Schema:        KeyringSchema,
		EnvelopeVer:   KeyringFileVersion,
		KDFTime:       argon2Time,
		KDFMemory:     argon2Memory,
		KDFThreads:    argon2Threads,
		Salt:          base64.StdEncoding.EncodeToString(salt),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		SealedKeyring: base64.StdEncoding.EncodeToString(ciphertext),
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal keyring file: %w", err)
	}
	return encoded, nil
}

// OpenKeyring unwraps keyring.enc with passphrase. A successful unwrap IS
// the passphrase check: there is no separate verifier to disagree with, and
// nothing else needs to be consulted to know the passphrase was right.
func OpenKeyring(encoded, passphrase []byte) (*Keyring, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("opening the keyring requires a passphrase")
	}
	if len(encoded) > maxKeyringBytes {
		return nil, fmt.Errorf("keyring exceeds size limit %d", maxKeyringBytes)
	}
	var file keyringFile
	if err := decodeJSONStrict(encoded, &file); err != nil {
		return nil, fmt.Errorf("parse keyring: %w", err)
	}
	if file.Schema != KeyringSchema {
		return nil, fmt.Errorf("unsupported keyring schema %q", file.Schema)
	}
	if file.EnvelopeVer != KeyringFileVersion {
		return nil, fmt.Errorf("unsupported keyring envelope version %d", file.EnvelopeVer)
	}
	if err := checkKDFParams(file.KDFTime, file.KDFMemory, file.KDFThreads); err != nil {
		return nil, err
	}
	salt, err := decodeCanonicalBase64("keyring salt", file.Salt)
	if err != nil {
		return nil, err
	}
	if len(salt) != masterSaltLen {
		return nil, fmt.Errorf("keyring salt has length %d, want %d", len(salt), masterSaltLen)
	}
	nonce, err := decodeCanonicalBase64("keyring nonce", file.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeCanonicalBase64("sealed keyring", file.SealedKeyring)
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
	plaintext, err := gcm.Open(nil, nonce, ciphertext, keyringHeaderAAD(
		file.Schema, file.EnvelopeVer,
		file.KDFTime, file.KDFMemory, file.KDFThreads, salt, nonce,
	))
	if err != nil {
		// A wrong passphrase and an edited header are indistinguishable by
		// construction, which is intended: the unwrap is the check.
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}
	defer ZeroBytes(plaintext)

	// Registered before the decode, not after the validation below: an
	// authenticated payload this release refuses — a multi-term root from a
	// later one — has already had its term keys written into these slices,
	// and a partial decode of malformed JSON can populate them too. Every
	// exit from here on zeroes them.
	var payload keyringPayload
	defer func() {
		for i := range payload.Terms {
			ZeroBytes(payload.Terms[i].Key)
		}
	}()
	if err := decodeJSONStrict(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("parse sealed keyring: %w", err)
	}
	if keyringDecodeHook != nil {
		keyringDecodeHook(payload.Terms)
	}
	if err := validateKeyringPayload(&payload); err != nil {
		return nil, err
	}
	// The v2 schema is durable now, but the runtime still holds exactly term
	// 1. Accepting its multi-term states before Open has an authority set and
	// StartRotation has the R5 pending guard would create the unguarded
	// transition the formal model's negative control demonstrates.
	if len(payload.Terms) != 1 {
		return nil, fmt.Errorf(
			"keyring holds %d terms; this release supports exactly one",
			len(payload.Terms),
		)
	}
	if payload.Terms[0].Term != FirstTerm || payload.CurrentTerm != FirstTerm {
		return nil, fmt.Errorf(
			"keyring names term %d current %d; this release supports only term %d",
			payload.Terms[0].Term, payload.CurrentTerm, FirstTerm,
		)
	}
	if len(payload.HistoricalAnchors) != 0 || payload.Rotation != nil {
		return nil, fmt.Errorf("this release does not yet accept rotation state or historical anchors")
	}
	kr := &Keyring{terms: make(map[int64][]byte, len(payload.Terms)), currentTerm: payload.CurrentTerm}
	for i := range payload.Terms {
		t := &payload.Terms[i]
		kr.terms[t.Term] = append([]byte(nil), t.Key...)
	}
	return kr, nil
}

// keyringDecodeHook is a test seam. When set it receives the decoded terms
// immediately after unmarshal and before any validation, so a test can hold
// the exact slices the decoder wrote and check they were zeroed on every exit
// path. Production leaves it nil.
var keyringDecodeHook func([]sealedTerm)

// checkKDFParams requires the exact tuple this release writes, before any of
// it reaches Argon2.
//
// These values are read before anything authenticates them — the KEK has to
// exist before the AEAD can verify the header — so whatever this accepts is
// work an edited root can compel. Ceilings would still leave a budget an
// attacker could spend, and there is nothing to spend it on: a store is
// readable only by the release that initialized it, so any tuple other than
// this one is corruption or tampering, never a store written elsewhere.
//
// Changing argon2Time, argon2Memory, or argon2Threads therefore means bumping
// KeyringFileVersion and the keystore marker version with them. Without that,
// every store the previous build wrote stops opening.
func checkKDFParams(kdfTime, kdfMemory uint32, kdfThreads uint8) error {
	if kdfTime != argon2Time || kdfMemory != argon2Memory || kdfThreads != argon2Threads {
		return fmt.Errorf(
			"keyring KDF parameters (%d, %d, %d) are not this release's (%d, %d, %d)",
			kdfTime, kdfMemory, kdfThreads, argon2Time, argon2Memory, argon2Threads,
		)
	}
	return nil
}

// sortedTerms returns the keyring's term numbers in ascending order, so the
// sealed payload is byte-stable for a given key set.
func (kr *Keyring) sortedTerms() []int64 {
	terms := make([]int64, 0, len(kr.terms))
	for term := range kr.terms {
		terms = append(terms, term)
	}
	slices.Sort(terms)
	return terms
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// aadFor builds the authenticated additional data binding an envelope to its
// term and to the object's logical identity.
//
// Every field is length-prefixed so no combination of class and selector can
// be reinterpreted as a different pair. The identity is logical, never a
// path: ciphertext moves between generations, into staging directories, and
// into deleted/ without re-encryption, and binding a path would make every
// one of those moves produce undecryptable data.
func aadFor(term int64, ctx ObjectContext) []byte {
	var out []byte
	out = appendAADField(out, []byte(aadDomain))
	var termBytes [8]byte
	binary.BigEndian.PutUint64(termBytes[:], uint64(term))
	out = appendAADField(out, termBytes[:])
	out = appendAADField(out, []byte(ctx.Class))
	out = appendAADField(out, []byte(ctx.Selector))
	return out
}

func validateKeyringPayload(payload *keyringPayload) error {
	if payload.Schema != KeyringSchema {
		return fmt.Errorf("unsupported sealed keyring schema %q", payload.Schema)
	}
	if payload.Terms == nil || len(payload.Terms) == 0 {
		return fmt.Errorf("keyring terms must be a non-empty array")
	}
	if payload.HistoricalAnchors == nil {
		return fmt.Errorf("keyring historical_anchors must be an array")
	}

	var previous int64
	for i := range payload.Terms {
		term := &payload.Terms[i]
		if term.Term < FirstTerm {
			return fmt.Errorf("invalid term ID %d", term.Term)
		}
		if i > 0 && term.Term <= previous {
			return fmt.Errorf("keyring terms are not strictly increasing")
		}
		if len(term.Key) != argon2KeyLen {
			return fmt.Errorf("term %d key has wrong length %d", term.Term, len(term.Key))
		}
		previous = term.Term
	}
	if payload.CurrentTerm != payload.Terms[len(payload.Terms)-1].Term {
		return fmt.Errorf(
			"current term %d is not the greatest resident term %d",
			payload.CurrentTerm, payload.Terms[len(payload.Terms)-1].Term,
		)
	}

	previousGeneration := ""
	for i, anchor := range payload.HistoricalAnchors {
		if err := storepaths.ValidateGenerationID(anchor.GenerationID); err != nil {
			return fmt.Errorf("historical anchor: %w", err)
		}
		if i > 0 && anchor.GenerationID <= previousGeneration {
			return fmt.Errorf("historical anchors are not strictly increasing by generation_id")
		}
		if anchor.SealSize <= 0 {
			return fmt.Errorf("historical anchor %s has invalid seal_size %d", anchor.GenerationID, anchor.SealSize)
		}
		if err := validateCanonicalSHA256(anchor.SealSHA256); err != nil {
			return fmt.Errorf("historical anchor %s seal_sha256: %w", anchor.GenerationID, err)
		}
		previousGeneration = anchor.GenerationID
	}

	if rotation := payload.Rotation; rotation != nil {
		if len(payload.Terms) < 2 {
			return fmt.Errorf("rotation requires current and retiring terms")
		}
		from := payload.Terms[len(payload.Terms)-2].Term
		if rotation.FromTerm != from || payload.CurrentTerm != from+1 {
			return fmt.Errorf(
				"rotation from_term %d is not immediately before current term %d",
				rotation.FromTerm, payload.CurrentTerm,
			)
		}
		if err := validateCanonicalSHA256(rotation.SnapshotSHA256); err != nil {
			return fmt.Errorf("rotation snapshot_sha256: %w", err)
		}
		if rotation.SnapshotSize <= 0 || rotation.SnapshotSize > maxRotationSnapshotBytes {
			return fmt.Errorf(
				"rotation snapshot_size %d is outside [1, %d]",
				rotation.SnapshotSize, maxRotationSnapshotBytes,
			)
		}
	}
	return nil
}

func validateCanonicalSHA256(value string) error {
	if len(value) != sha256HexLength {
		return fmt.Errorf("must be %d lowercase hexadecimal characters", sha256HexLength)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("must be %d lowercase hexadecimal characters", sha256HexLength)
	}
	return nil
}

const sha256HexLength = 64

func decodeCanonicalBase64(label, value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		ZeroBytes(decoded)
		return nil, fmt.Errorf("%s is not canonical base64", label)
	}
	return decoded, nil
}

func decodeJSONStrict(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	switch err := decoder.Decode(&trailing); err {
	case io.EOF:
		return nil
	case nil:
		return fmt.Errorf("trailing data after JSON document")
	default:
		return fmt.Errorf("trailing data after JSON document: %w", err)
	}
}

// appendAADField appends one length-prefixed field. The prefix is what stops
// two different field splits from producing the same byte string.
func appendAADField(out, field []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(field)))
	out = append(out, n[:]...)
	return append(out, field...)
}

// keyringHeaderAAD binds the root file's plaintext header to its sealed body.
//
// Editing the salt, the KDF parameters, or the nonce already fails closed by
// producing the wrong key or the wrong keystream, but the schema and version
// fields have no such effect: without this, they are checked only by the
// explicit comparisons in OpenKeyring, which is validation rather than
// authentication. Binding the whole header makes it cryptographic, for the
// same reason the term envelope binds its own header.
func keyringHeaderAAD(schema string, version int, kdfTime, kdfMemory uint32, kdfThreads uint8, salt, nonce []byte) []byte {
	var out []byte
	out = appendAADField(out, []byte(keyringAADDomain))
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
