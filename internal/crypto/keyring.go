// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	FirstTerm       = 1
	maxKeyringBytes = 1 << 20
	sha256HexLength = 64
)

var ErrKeyringNotOpen = errors.New("keyring is not open")

// keyringFile is the wrapped subobject embedded in store-root.enc. It is not
// independently addressable or accepted as a standalone file.
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

type sealedTerm struct {
	Term int64  `json:"term"`
	Key  []byte `json:"key"`
}

// HistoricalGenerationAnchor pins one retained generation's exact seal.
type HistoricalGenerationAnchor struct {
	GenerationID string `json:"generation_id"`
	SealSize     int64  `json:"seal_size"`
	SealSHA256   string `json:"seal_sha256"`
}

// Keyring holds term keys only for an unlocked session. Live state is
// authorized exclusively by currentTerm; older terms require an exact
// historical-generation anchor before they can be used.
type Keyring struct {
	terms             map[int64][]byte
	currentTerm       int64
	historicalAnchors []HistoricalGenerationAnchor
}

func NewKeyring() (*Keyring, error) {
	key, err := randomBytes(argon2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("generate term key: %w", err)
	}
	return &Keyring{
		terms: map[int64][]byte{FirstTerm: key}, currentTerm: FirstTerm,
		historicalAnchors: []HistoricalGenerationAnchor{},
	}, nil
}

// NewSuccessorKeyring adds exactly one fresh term and replaces the complete
// historical-anchor set without mutating current.
func NewSuccessorKeyring(current *Keyring, anchors []HistoricalGenerationAnchor) (*Keyring, error) {
	if current == nil || len(current.terms) == 0 {
		return nil, ErrKeyringNotOpen
	}
	if anchors == nil {
		return nil, fmt.Errorf("successor keyring historical anchors must be an array")
	}
	if current.currentTerm == math.MaxInt64 {
		return nil, fmt.Errorf("key term is exhausted")
	}
	if err := requirePreservedHistoricalAnchors(current.historicalAnchors, anchors); err != nil {
		return nil, err
	}
	successor, err := cloneKeyring(current)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			successor.Zero()
		}
	}()
	term := current.currentTerm + 1
	key, err := randomBytes(argon2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("generate successor term: %w", err)
	}
	successor.terms[term] = key
	successor.currentTerm = term
	successor.historicalAnchors = slices.Clone(anchors)
	payload := storeRootKeyringPayload{
		Schema: StoreRootKeyringSchema, CurrentTerm: term,
		Terms: sealedTermsFromKeyring(successor), HistoricalAnchors: slices.Clone(anchors),
	}
	if err := validateStoreRootKeyringPayload(&payload); err != nil {
		return nil, fmt.Errorf("invalid successor keyring: %w", err)
	}
	success = true
	return successor, nil
}

// The following constructors exist only for confined tests.
func NewKeyringFromKey(key []byte) (*Keyring, error) {
	return NewKeyringFromTermKey(FirstTerm, key)
}

func NewKeyringFromTermKey(term int64, key []byte) (*Keyring, error) {
	if term < FirstTerm {
		return nil, fmt.Errorf("term must be at least %d, got %d", FirstTerm, term)
	}
	if len(key) != argon2KeyLen {
		return nil, fmt.Errorf("term key must be %d bytes, got %d", argon2KeyLen, len(key))
	}
	return &Keyring{
		terms: map[int64][]byte{term: slices.Clone(key)}, currentTerm: term,
		historicalAnchors: []HistoricalGenerationAnchor{},
	}, nil
}

func NewKeyringFromTermKeys(currentTerm int64, terms map[int64][]byte) (*Keyring, error) {
	if len(terms) == 0 {
		return nil, fmt.Errorf("keyring terms must not be empty")
	}
	greatest := int64(0)
	adopted := make(map[int64][]byte, len(terms))
	for term, key := range terms {
		if term < FirstTerm || len(key) != argon2KeyLen {
			zeroTermMap(adopted)
			return nil, fmt.Errorf("invalid term %d key", term)
		}
		adopted[term] = slices.Clone(key)
		greatest = max(greatest, term)
	}
	if currentTerm != greatest {
		zeroTermMap(adopted)
		return nil, fmt.Errorf("current term %d is not greatest resident term %d", currentTerm, greatest)
	}
	return &Keyring{
		terms: adopted, currentTerm: currentTerm,
		historicalAnchors: []HistoricalGenerationAnchor{},
	}, nil
}

func (kr *Keyring) CurrentTerm() int64 { return kr.currentTerm }

func (kr *Keyring) HistoricalGenerationAnchors() []HistoricalGenerationAnchor {
	if kr == nil {
		return nil
	}
	return slices.Clone(kr.historicalAnchors)
}

func (kr *Keyring) HistoricalGenerationAnchor(generationID string) (HistoricalGenerationAnchor, bool) {
	if kr == nil {
		return HistoricalGenerationAnchor{}, false
	}
	index, found := slices.BinarySearchFunc(kr.historicalAnchors, generationID,
		func(anchor HistoricalGenerationAnchor, target string) int {
			return strings.Compare(anchor.GenerationID, target)
		})
	if !found {
		return HistoricalGenerationAnchor{}, false
	}
	return kr.historicalAnchors[index], true
}

func (kr *Keyring) Zero() {
	if kr == nil {
		return
	}
	zeroTermMap(kr.terms)
	kr.currentTerm = 0
	kr.historicalAnchors = nil
}

func (kr *Keyring) Seal(plaintext []byte, ctx ObjectContext) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, ErrKeyringNotOpen
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

func (kr *Keyring) Open(sealed []byte, ctx ObjectContext) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, ErrKeyringNotOpen
	}
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	term, err := envelopeTerm(sealed)
	if err != nil {
		return nil, err
	}
	if term != kr.currentTerm {
		return nil, fmt.Errorf("term %d is not authorized for current state", term)
	}
	return openUnderTerm(sealed, kr.terms[term], term, ctx)
}

func (kr *Keyring) authorizesCurrentStateTerm(term int64) bool {
	return kr != nil && term == kr.currentTerm
}

func (kr *Keyring) OpenHistoricalGenerationEnvelope(sealed []byte, ctx ObjectContext, expectedTerm int64) ([]byte, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, ErrKeyringNotOpen
	}
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	term, err := envelopeTerm(sealed)
	if err != nil {
		return nil, err
	}
	if expectedTerm < FirstTerm || term != expectedTerm {
		return nil, fmt.Errorf("historical generation envelope term %d does not match sealed entry term %d", term, expectedTerm)
	}
	key, ok := kr.terms[term]
	if !ok {
		return nil, fmt.Errorf("keyring has no key for historical term %d", term)
	}
	return openUnderTerm(sealed, key, term, ctx)
}

// VerifyKnownTermEnvelope authenticates one exact envelope buffer under its
// logical context without releasing plaintext. It is confined to
// non-authoritative quarantine classification: absence of a resident term is
// reported separately from cryptographic failure so an older restored root
// can preserve an orphaned post-changepass publication.
func (kr *Keyring) VerifyKnownTermEnvelope(sealed []byte, ctx ObjectContext) (term int64, available bool, err error) {
	if kr == nil || len(kr.terms) == 0 {
		return 0, false, ErrKeyringNotOpen
	}
	if err := ctx.validate(); err != nil {
		return 0, false, err
	}
	term, err = envelopeTerm(sealed)
	if err != nil {
		return 0, false, err
	}
	key, ok := kr.terms[term]
	if !ok {
		return term, false, nil
	}
	plaintext, err := openUnderTerm(sealed, key, term, ctx)
	if plaintext != nil {
		ZeroBytes(plaintext)
	}
	if err != nil {
		return term, true, err
	}
	return term, true, nil
}

func (kr *Keyring) sortedTerms() []int64 {
	terms := make([]int64, 0, len(kr.terms))
	for term := range kr.terms {
		terms = append(terms, term)
	}
	slices.Sort(terms)
	return terms
}

func sealedTermsFromKeyring(kr *Keyring) []sealedTerm {
	terms := make([]sealedTerm, 0, len(kr.terms))
	for _, term := range kr.sortedTerms() {
		terms = append(terms, sealedTerm{Term: term, Key: kr.terms[term]})
	}
	return terms
}

func cloneKeyring(kr *Keyring) (*Keyring, error) {
	if kr == nil || len(kr.terms) == 0 {
		return nil, ErrKeyringNotOpen
	}
	cloned := &Keyring{
		terms: make(map[int64][]byte, len(kr.terms)), currentTerm: kr.currentTerm,
		historicalAnchors: slices.Clone(kr.historicalAnchors),
	}
	for term, key := range kr.terms {
		cloned.terms[term] = slices.Clone(key)
	}
	return cloned, nil
}

func requirePreservedHistoricalAnchors(existing, replacement []HistoricalGenerationAnchor) error {
	for _, anchor := range existing {
		index, found := slices.BinarySearchFunc(replacement, anchor.GenerationID,
			func(candidate HistoricalGenerationAnchor, generationID string) int {
				return strings.Compare(candidate.GenerationID, generationID)
			})
		if !found || replacement[index] != anchor {
			return fmt.Errorf("historical anchor for generation %s would be dropped or changed", anchor.GenerationID)
		}
	}
	return nil
}

func NewHistoricalGenerationAnchor(generationID string, exactSeal []byte) (HistoricalGenerationAnchor, error) {
	sum := sha256.Sum256(exactSeal)
	anchor := HistoricalGenerationAnchor{
		GenerationID: generationID, SealSize: int64(len(exactSeal)),
		SealSHA256: hex.EncodeToString(sum[:]),
	}
	if err := anchor.Validate(); err != nil {
		return HistoricalGenerationAnchor{}, err
	}
	return anchor, nil
}

func (anchor HistoricalGenerationAnchor) Validate() error {
	if err := storepaths.ValidateGenerationID(anchor.GenerationID); err != nil {
		return err
	}
	if anchor.SealSize <= 0 {
		return fmt.Errorf("historical anchor %s has invalid seal_size %d", anchor.GenerationID, anchor.SealSize)
	}
	if err := validateCanonicalSHA256(anchor.SealSHA256); err != nil {
		return fmt.Errorf("historical anchor %s seal_sha256: %w", anchor.GenerationID, err)
	}
	return nil
}

func (anchor HistoricalGenerationAnchor) VerifyExact(generationID string, data []byte) error {
	if err := anchor.Validate(); err != nil {
		return err
	}
	if anchor.GenerationID != generationID {
		return fmt.Errorf("historical anchor names generation %s, want %s", anchor.GenerationID, generationID)
	}
	if int64(len(data)) != anchor.SealSize {
		return fmt.Errorf("generation %s seal size %d does not match anchor size %d", generationID, len(data), anchor.SealSize)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != anchor.SealSHA256 {
		return fmt.Errorf("generation %s seal digest does not match historical anchor", generationID)
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func aadFor(term int64, ctx ObjectContext) []byte {
	var numeric [8]byte
	out := appendAADField(nil, []byte(aadDomain))
	binary.BigEndian.PutUint64(numeric[:], uint64(term))
	out = appendAADField(out, numeric[:])
	out = appendAADField(out, []byte(ctx.Class))
	return appendAADField(out, []byte(ctx.Selector))
}

func checkKDFParams(kdfTime, kdfMemory uint32, kdfThreads uint8) error {
	if kdfTime != argon2Time || kdfMemory != argon2Memory || kdfThreads != argon2Threads {
		return fmt.Errorf("keyring KDF parameters (%d, %d, %d) are not this release's (%d, %d, %d)",
			kdfTime, kdfMemory, kdfThreads, argon2Time, argon2Memory, argon2Threads)
	}
	return nil
}

var keyringDecodeHook func([]sealedTerm)

func zeroTermMap(terms map[int64][]byte) {
	for term, key := range terms {
		ZeroBytes(key)
		delete(terms, term)
	}
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

func appendAADField(out, field []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(field)))
	out = append(out, n[:]...)
	return append(out, field...)
}
