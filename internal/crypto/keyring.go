// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
)

// The keyring is the store's single cryptographic root
// (docs/PROPOSAL_KEYTERM_ROTATION.md). It is self-contained: it carries its
// own KDF parameters and salt in the clear and an AEAD-sealed set of key
// terms. Successful unwrap is the passphrase check, so no separate verifier
// exists and a passphrase change is one atomic file write.
//
// Phase 1 holds exactly one term. Term append, the rewrap window, and
// historical anchors are phase 3 and are deliberately absent here.
const (
	// KeyringSchema identifies the sealed keyring payload.
	KeyringSchema = "aplane.keyring.v1"
	// KeyringFileVersion is the on-disk envelope version for keyring.enc.
	KeyringFileVersion = 1

	// keyringAADDomain separates the root file's header binding from the term
	// envelope's, so neither construction's bytes can be replayed as the
	// other's.
	keyringAADDomain = "aplane.keyring-file.v1"

	// KDF ceilings bound the work a root file can ask for. The parameters
	// are recorded per file so they can be raised without a code change, but
	// they are read before anything authenticates them: the header binding
	// cannot help here, because the KEK must be derived before the AEAD can
	// verify anything. An unbounded value in a damaged or edited root would
	// otherwise hang or OOM a daemon that serves every other identity too.
	//
	// The ceilings sit far above the current tuple (t=2, 64 MiB, p=4) so
	// future hardening does not need to move them.
	maxKDFTime    = 16
	maxKDFMemory  = 1 << 20 // 1 GiB, expressed in KiB as Argon2 takes it
	maxKDFThreads = 16
	// FirstTerm is the term every store is initialized with.
	FirstTerm = 1

	maxKeyringBytes = 1 << 20
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
	Schema      string       `json:"schema"`
	CurrentTerm int          `json:"current_term"`
	Terms       []sealedTerm `json:"terms"`
}

type sealedTerm struct {
	Term int    `json:"term"`
	Key  []byte `json:"key"`
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
	terms       map[int][]byte
	currentTerm int
}

// NewKeyring creates a keyring holding one freshly generated term.
func NewKeyring() (*Keyring, error) {
	key, err := randomBytes(argon2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("generate term key: %w", err)
	}
	return &Keyring{
		terms:       map[int][]byte{FirstTerm: key},
		currentTerm: FirstTerm,
	}, nil
}

// NewKeyringFromKey adopts an existing key as the first term. It exists so a
// store can be created with a key derived elsewhere; ordinary creation uses
// NewKeyring.
func NewKeyringFromKey(key []byte) (*Keyring, error) {
	if len(key) != argon2KeyLen {
		return nil, fmt.Errorf("term key must be %d bytes, got %d", argon2KeyLen, len(key))
	}
	return &Keyring{
		terms:       map[int][]byte{FirstTerm: slices.Clone(key)},
		currentTerm: FirstTerm,
	}, nil
}

// CurrentTerm returns the term new writes use.
func (kr *Keyring) CurrentTerm() int { return kr.currentTerm }

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
// Phase 1 holds one term, so "the term the envelope names" is always the
// current one. The lookup is written term-generally because phase 3 adds
// retiring terms, but no authority split exists yet: that belongs with the
// rewrap window, which phase 1 does not have.
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

// CurrentTermKey returns a copy of the current term's key bytes.
//
// This is the phase-1 compatibility seam: it exists so call sites that still
// take a raw key keep working while only one term exists. The copy is
// deliberate — the caller owns the returned slice and must zero it when done,
// and no caller can reach into the keyring's own storage through it.
//
// Phase 2 migrates those callers to Seal/Open and deletes this method, which
// turns "did every site move?" into a compile error.
func (kr *Keyring) CurrentTermKey() ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, fmt.Errorf("keyring is not open")
	}
	key, ok := kr.terms[kr.currentTerm]
	if !ok {
		return nil, fmt.Errorf("keyring has no key for current term %d", kr.currentTerm)
	}
	return append([]byte(nil), key...), nil
}

// IntegrityKey derives the HMAC key for one integrity domain from the
// current term. It returns key material because the HMAC construction lives
// in callers today; phase 3 replaces it with SignIntegrity/VerifyIntegrity
// so that material stops leaving this package.
//
// Nothing calls this yet — the integrity sidecars still reach the term key
// through the WithMasterKey seam. When they move here, the output must stay
// byte-identical to DerivePolicyIntegrityKey and DeriveNodeRoleIntegrityKey
// for the same key and info: the HKDF inputs are (key, info) and adding a
// salt or a domain string here would silently invalidate every sidecar
// already on disk.
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
	plaintext, err := json.Marshal(keyringPayload{
		Schema:      KeyringSchema,
		CurrentTerm: kr.currentTerm,
		Terms:       terms,
	})
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
	if err := json.Unmarshal(encoded, &file); err != nil {
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
	salt, err := base64.StdEncoding.DecodeString(file.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode keyring salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode keyring nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(file.SealedKeyring)
	if err != nil {
		return nil, fmt.Errorf("decode sealed keyring: %w", err)
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

	var payload keyringPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("parse sealed keyring: %w", err)
	}
	if payload.Schema != KeyringSchema {
		return nil, fmt.Errorf("unsupported sealed keyring schema %q", payload.Schema)
	}
	// This release holds exactly term 1, and enforces it rather than assuming
	// it. Accepting a multi-term root here would let a phase-1 binary read a
	// keyring written by a release that has retiring terms and an authority
	// split, and read it without either — reauthorizing a retired term for
	// current state. Relaxing this is phase 3's job, and doing so requires
	// bumping the file version and the marker alongside it.
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
	kr := &Keyring{terms: make(map[int][]byte, len(payload.Terms)), currentTerm: payload.CurrentTerm}
	for i := range payload.Terms {
		t := &payload.Terms[i]
		// The decoder wrote these bytes into a slice we own, so they can be
		// zeroed once copied into the keyring.
		defer ZeroBytes(t.Key)
		if len(t.Key) != argon2KeyLen {
			kr.Zero()
			return nil, fmt.Errorf("term %d key has wrong length %d", t.Term, len(t.Key))
		}
		kr.terms[t.Term] = append([]byte(nil), t.Key...)
	}
	return kr, nil
}

// checkKDFParams rejects a root whose KDF parameters are absent or beyond
// what this release is willing to spend, before any of them reach Argon2.
func checkKDFParams(kdfTime, kdfMemory uint32, kdfThreads uint8) error {
	if kdfTime == 0 || kdfMemory == 0 || kdfThreads == 0 {
		return fmt.Errorf("keyring has incomplete KDF parameters")
	}
	if kdfTime > maxKDFTime {
		return fmt.Errorf("keyring kdf_time %d exceeds the limit %d", kdfTime, maxKDFTime)
	}
	if kdfMemory > maxKDFMemory {
		return fmt.Errorf("keyring kdf_memory %d exceeds the limit %d", kdfMemory, maxKDFMemory)
	}
	if kdfThreads > maxKDFThreads {
		return fmt.Errorf("keyring kdf_threads %d exceeds the limit %d", kdfThreads, maxKDFThreads)
	}
	return nil
}

// sortedTerms returns the keyring's term numbers in ascending order, so the
// sealed payload is byte-stable for a given key set.
func (kr *Keyring) sortedTerms() []int {
	terms := make([]int, 0, len(kr.terms))
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
func aadFor(term int, ctx ObjectContext) []byte {
	var out []byte
	out = appendAADField(out, []byte(aadDomain))
	var termBytes [8]byte
	binary.BigEndian.PutUint64(termBytes[:], uint64(term))
	out = appendAADField(out, termBytes[:])
	out = appendAADField(out, []byte(ctx.Class))
	out = appendAADField(out, []byte(ctx.Selector))
	return out
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
