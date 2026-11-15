// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The lookup decodes the Indexer's answer itself, into the few fields it
// reads, under one set of rules:
//
//  1. The whole body is read first, up to MaxIndexerResponseBytes; a longer
//     body is refused before anything is decoded.
//  2. The body must be one JSON document, checked whole by json.Valid: one
//     value, then only whitespace. A syntax error anywhere, trailing data or
//     a truncated document refuses it, wherever a matching result is.
//  3. That value must be an object. Its transactions key may appear once,
//     holding an array (or null) of at most lookupLimit objects; a second
//     transactions key, or an element past the limit, refuses the answer.
//     Every element is read to the end of the document, and only then is
//     the first whose top-level sender is the account picked.
//  4. In every object the lookup reads (the top level, each result, its
//     signature and signature.logicsig), keys are compared byte for byte
//     with the names below: no case or Unicode folding, and a key written
//     with an escape sequence refuses the answer. A key the lookup reads
//     appearing twice in one object refuses it too.
//  5. Each field read has a fixed bound and form (below). Every other value,
//     at any depth, is scanned past without being kept.
//
// What is read, by the Indexer's JSON names (the SDK's models name them the
// same way):
//
//	transactions[].id, sender, rekey-to, auth-addr, confirmed-round, genesis-hash
//	transactions[].signature.sig, multisig, pqsig                  (presence only)
//	transactions[].signature.logicsig.logic
//	transactions[].signature.logicsig.signature, multisig-signature,
//	  logic-multisig-signature, pqsig                             (presence only)
//
// So memory is the body buffer plus at most lookupLimit results of bounded
// fields, whatever the body holds.

// Field bounds and forms. A string field must be a JSON string without
// escape sequences (the Indexer writes base32 and base64 plainly) no longer
// than its bound, or null; confirmed-round a JSON integer that fits a uint64,
// or null.
const (
	// txIDLength is a transaction ID's length: unpadded base32 of 32 bytes.
	txIDLength = 52
	// addressLength is an address's length: base32 of 32 bytes and a
	// 4-byte checksum.
	addressLength = 58
	// genesisHashBytes is a genesis hash's length.
	genesisHashBytes = 32
	// maxLogicBytes bounds a LogicSig program: a group pools at most
	// LogicSigMaxSize (1,000) bytes of program and arguments per
	// transaction, so no program is longer than 1,000 times the largest
	// group.
	maxLogicBytes = 1000 * types.MaxTxGroupSize
)

var (
	errMalformedPage   = errors.New("indexer response is malformed")
	errTooManyResults  = errors.New("indexer returned more results than asked")
	errFieldTooLong    = errors.New("indexer response field exceeds its bound")
	errFieldNotAString = errors.New("indexer response field is not a plain string")
	errDuplicateKey    = errors.New("indexer response repeats a key")
	errEscapedKey      = errors.New("indexer response writes a key with an escape sequence")
)

// indexerTxn is what the lookup reads of one result.
type indexerTxn struct {
	ID             string
	Sender         string
	RekeyTo        string
	AuthAddr       string
	ConfirmedRound uint64
	GenesisHash    []byte
	Signature      struct {
		Sig, Multisig, Pqsig bool
		Logicsig             struct {
			Logic                                                       []byte
			Signature, MultisigSignature, LogicMultisigSignature, Pqsig bool
		}
	}
}

// decodeNewest decodes data, the whole body, and returns the first result
// whose top-level sender is sender, or nil when none is.
func decodeNewest(data []byte, sender string) (*indexerTxn, error) {
	if !json.Valid(data) {
		return nil, errMalformedPage
	}
	w := walker{data: data}
	w.space()
	if !w.at('{') {
		return nil, errMalformedPage
	}
	var match *indexerTxn
	seen := false
	err := w.object(func(key []byte) error {
		if string(key) != "transactions" {
			return w.skip()
		}
		if seen {
			return errDuplicateKey
		}
		seen = true
		var err error
		match, err = w.results(sender)
		return err
	})
	if err != nil {
		return nil, err
	}
	return match, nil
}

// results reads the transactions array: every element, at most
// lookupLimit, keeping the first sent by sender.
func (w *walker) results(sender string) (*indexerTxn, error) {
	if w.null() {
		return nil, nil
	}
	if !w.at('[') {
		return nil, errMalformedPage
	}
	var match *indexerTxn
	n := 0
	err := w.array(func() error {
		if n == lookupLimit {
			return errTooManyResults
		}
		n++
		txn, err := w.result()
		if err == nil && match == nil && txn.Sender == sender {
			match = txn
		}
		return err
	})
	return match, err
}

// Bits of the keys read in a result, its signature and its logicsig, for the
// duplicate check.
const (
	keyID = 1 << iota
	keySender
	keyRekeyTo
	keyAuthAddr
	keyConfirmedRound
	keyGenesisHash
	keySignature
)

func (w *walker) result() (*indexerTxn, error) {
	if !w.at('{') {
		return nil, errMalformedPage
	}
	txn := &indexerTxn{}
	var seen uint
	err := w.object(func(key []byte) error {
		var bit uint
		switch string(key) {
		case "id":
			bit = keyID
		case "sender":
			bit = keySender
		case "rekey-to":
			bit = keyRekeyTo
		case "auth-addr":
			bit = keyAuthAddr
		case "confirmed-round":
			bit = keyConfirmedRound
		case "genesis-hash":
			bit = keyGenesisHash
		case "signature":
			bit = keySignature
		default:
			return w.skip()
		}
		if seen&bit != 0 {
			return errDuplicateKey
		}
		seen |= bit
		var err error
		switch bit {
		case keyID:
			txn.ID, err = w.text(txIDLength)
		case keySender:
			txn.Sender, err = w.text(addressLength)
		case keyRekeyTo:
			txn.RekeyTo, err = w.text(addressLength)
		case keyAuthAddr:
			txn.AuthAddr, err = w.text(addressLength)
		case keyConfirmedRound:
			txn.ConfirmedRound, err = w.uint()
		case keyGenesisHash:
			txn.GenesisHash, err = w.base64(genesisHashBytes)
		case keySignature:
			err = w.signature(txn)
		}
		return err
	})
	return txn, err
}

const (
	sigSig = 1 << iota
	sigMultisig
	sigPqsig
	sigLogicsig
)

func (w *walker) signature(txn *indexerTxn) error {
	if w.null() {
		return nil
	}
	if !w.at('{') {
		return errMalformedPage
	}
	sig := &txn.Signature
	var seen uint
	return w.object(func(key []byte) error {
		var bit uint
		var present *bool
		switch string(key) {
		case "sig":
			bit, present = sigSig, &sig.Sig
		case "multisig":
			bit, present = sigMultisig, &sig.Multisig
		case "pqsig":
			bit, present = sigPqsig, &sig.Pqsig
		case "logicsig":
			bit = sigLogicsig
		default:
			return w.skip()
		}
		if seen&bit != 0 {
			return errDuplicateKey
		}
		seen |= bit
		if present != nil {
			*present = w.presence()
			return w.skip()
		}
		return w.logicsig(txn)
	})
}

const (
	lsigLogic = 1 << iota
	lsigSignature
	lsigMultisigSignature
	lsigLogicMultisigSignature
	lsigPqsig
)

func (w *walker) logicsig(txn *indexerTxn) error {
	if w.null() {
		return nil
	}
	if !w.at('{') {
		return errMalformedPage
	}
	lsig := &txn.Signature.Logicsig
	var seen uint
	return w.object(func(key []byte) error {
		var bit uint
		var present *bool
		switch string(key) {
		case "logic":
			bit = lsigLogic
		case "signature":
			bit, present = lsigSignature, &lsig.Signature
		case "multisig-signature":
			bit, present = lsigMultisigSignature, &lsig.MultisigSignature
		case "logic-multisig-signature":
			bit, present = lsigLogicMultisigSignature, &lsig.LogicMultisigSignature
		case "pqsig":
			bit, present = lsigPqsig, &lsig.Pqsig
		default:
			return w.skip()
		}
		if seen&bit != 0 {
			return errDuplicateKey
		}
		seen |= bit
		if present != nil {
			*present = w.presence()
			return w.skip()
		}
		var err error
		lsig.Logic, err = w.base64(maxLogicBytes)
		return err
	})
}

// walker reads a document json.Valid has accepted, so it skips values by
// their delimiters alone. It keeps a position and nothing else.
type walker struct {
	data []byte
	pos  int
}

func (w *walker) space() {
	for w.pos < len(w.data) {
		switch w.data[w.pos] {
		case ' ', '\t', '\n', '\r':
			w.pos++
		default:
			return
		}
	}
}

func (w *walker) at(c byte) bool { return w.pos < len(w.data) && w.data[w.pos] == c }

// null consumes a null value and reports whether there was one.
func (w *walker) null() bool {
	if w.pos+4 <= len(w.data) && string(w.data[w.pos:w.pos+4]) == "null" {
		w.pos += 4
		return true
	}
	return false
}

// object reads the object at the position, calling member with each key as
// written, positioned at the key's value, which member must consume.
func (w *walker) object(member func(key []byte) error) error {
	w.pos++ // '{'
	for {
		w.space()
		if w.at('}') {
			w.pos++
			return nil
		}
		if w.at(',') {
			w.pos++
			w.space()
		}
		key, escaped := w.rawString()
		if escaped {
			return errEscapedKey
		}
		w.space()
		w.pos++ // ':'
		w.space()
		if err := member(key); err != nil {
			return err
		}
	}
}

// array reads the array at the position, calling element positioned at each
// element, which element must consume.
func (w *walker) array(element func() error) error {
	w.pos++ // '['
	for {
		w.space()
		if w.at(']') {
			w.pos++
			return nil
		}
		if w.at(',') {
			w.pos++
			w.space()
		}
		if err := element(); err != nil {
			return err
		}
	}
}

// rawString consumes the string at the position and returns its content as
// written, a slice of the body, and whether it holds an escape sequence.
// Comparing it with a constant through string() allocates nothing; the
// callers that keep it bound its length first.
func (w *walker) rawString() ([]byte, bool) {
	start := w.pos + 1
	escaped := false
	i := start
	for ; i < len(w.data); i++ {
		if c := w.data[i]; c == '\\' {
			escaped = true
			i++
		} else if c == '"' {
			break
		}
	}
	w.pos = i + 1
	return w.data[start:i], escaped
}

// skip consumes one value of any kind.
func (w *walker) skip() error {
	if w.pos >= len(w.data) {
		return errMalformedPage
	}
	switch w.data[w.pos] {
	case '"':
		w.rawString()
	case '{', '[':
		depth := 0
		for ; w.pos < len(w.data); w.pos++ {
			switch w.data[w.pos] {
			case '"':
				w.rawString()
				w.pos--
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					w.pos++
					return nil
				}
			}
		}
		return errMalformedPage
	default: // number, true, false, null
		for w.pos < len(w.data) {
			switch w.data[w.pos] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return nil
			}
			w.pos++
		}
	}
	return nil
}

// presence reports whether the value at the position holds anything: any
// value but null, an empty string, an empty object or an empty array. It
// does not consume the value.
func (w *walker) presence() bool {
	switch {
	case w.pos+4 <= len(w.data) && string(w.data[w.pos:w.pos+4]) == "null":
		return false
	case w.at('"'):
		return w.pos+1 < len(w.data) && w.data[w.pos+1] != '"'
	case w.at('{') || w.at('['):
		close := byte('}')
		if w.at('[') {
			close = ']'
		}
		i := w.pos + 1
		for i < len(w.data) && (w.data[i] == ' ' || w.data[i] == '\t' || w.data[i] == '\n' || w.data[i] == '\r') {
			i++
		}
		return i >= len(w.data) || w.data[i] != close
	}
	return true
}

// text consumes a string field of at most max bytes, written without escape
// sequences, or null.
func (w *walker) text(max int) (string, error) {
	if w.null() {
		return "", nil
	}
	if !w.at('"') {
		return "", errFieldNotAString
	}
	s, escaped := w.rawString()
	switch {
	case escaped:
		return "", errFieldNotAString
	case len(s) > max:
		return "", fmt.Errorf("%w: %d bytes, at most %d", errFieldTooLong, len(s), max)
	}
	return string(s), nil
}

// base64 consumes a field of standard base64 holding at most maxBytes, or
// null. Padding lets a few more bytes share the longest encoding, so the
// decoded length is checked too.
func (w *walker) base64(maxBytes int) ([]byte, error) {
	if w.null() {
		return nil, nil
	}
	if !w.at('"') {
		return nil, errFieldNotAString
	}
	s, escaped := w.rawString()
	switch {
	case escaped:
		return nil, errFieldNotAString
	case len(s) > base64.StdEncoding.EncodedLen(maxBytes):
		return nil, fmt.Errorf("%w: %d bytes encoded, at most %d decoded", errFieldTooLong, len(s), maxBytes)
	}
	out := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
	n, err := base64.StdEncoding.Decode(out, s)
	if err != nil {
		return nil, errMalformedPage
	}
	if n > maxBytes {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", errFieldTooLong, n, maxBytes)
	}
	return out[:n], nil
}

// uint consumes a JSON integer that fits a uint64, or null.
func (w *walker) uint() (uint64, error) {
	if w.null() {
		return 0, nil
	}
	var v uint64
	digits := 0
	for w.pos < len(w.data) && w.data[w.pos] >= '0' && w.data[w.pos] <= '9' {
		d := uint64(w.data[w.pos] - '0')
		if v > (^uint64(0)-d)/10 {
			return 0, errMalformedPage
		}
		v = v*10 + d
		digits++
		w.pos++
	}
	if digits == 0 {
		return 0, errMalformedPage
	}
	// A fraction or exponent follows the digits of a number that is not an
	// integer.
	if w.pos < len(w.data) {
		switch w.data[w.pos] {
		case '.', 'e', 'E':
			return 0, errMalformedPage
		}
	}
	return v, nil
}
