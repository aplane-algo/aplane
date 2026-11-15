// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package chainread

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The lookup decodes an Indexer page itself, from the capped body, into the
// few fields it reads. The SDK's models would hold every field of every
// result, several kilobytes each, so a 1 MiB body of empty objects would
// cost gigabytes; here memory is bounded by the body cap and the page size.
//
// What is read, by the Indexer's JSON names:
//
//	next-token
//	transactions[].id, sender, rekey-to, auth-addr, confirmed-round, genesis-hash
//	transactions[].signature.sig, multisig, pqsig                  (presence only)
//	transactions[].signature.logicsig.logic
//	transactions[].signature.logicsig.signature, multisig-signature,
//	  logic-multisig-signature, pqsig                             (presence only)
//
// Every other field, at any depth (current-round, args, inner-txns, notes,
// a newer Indexer's additions), is scanned past and never kept.

// Field bounds. A field longer than its bound refuses the page.
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
	// maxNextTokenLength bounds the Indexer's opaque page token.
	maxNextTokenLength = 256
)

var (
	errMalformedPage   = errors.New("indexer response is malformed")
	errTooManyResults  = errors.New("indexer returned more results than asked")
	errFieldTooLong    = errors.New("indexer response field exceeds its bound")
	errFieldNotAString = errors.New("indexer response field is not a string")
)

// indexerTxn is what the lookup reads of one result.
type indexerTxn struct {
	ID             txIDText    `json:"id"`
	Sender         addressText `json:"sender"`
	RekeyTo        addressText `json:"rekey-to"`
	AuthAddr       addressText `json:"auth-addr"`
	ConfirmedRound uint64      `json:"confirmed-round"`
	GenesisHash    hashBytes   `json:"genesis-hash"`
	Signature      struct {
		Sig      presence `json:"sig"`
		Multisig presence `json:"multisig"`
		Pqsig    presence `json:"pqsig"`
		Logicsig struct {
			Logic                  programBytes `json:"logic"`
			Signature              presence     `json:"signature"`
			MultisigSignature      presence     `json:"multisig-signature"`
			LogicMultisigSignature presence     `json:"logic-multisig-signature"`
			Pqsig                  presence     `json:"pqsig"`
		} `json:"logicsig"`
	} `json:"signature"`
}

// indexerPage is what the lookup keeps of one search page: the first result
// the account sent that rekeys it, if any, and the next page's token.
type indexerPage struct {
	match *indexerTxn
	next  string
}

// decodePage reads one page from body, a result at a time. It stops at the
// first result whose top-level sender is sender and which rekeys it, and
// refuses a page that holds more than lookupPageSize results before
// decoding the one past the limit.
func decodePage(body io.Reader, sender string) (indexerPage, error) {
	var page indexerPage
	dec := json.NewDecoder(body)
	if err := expectDelim(dec, '{'); err != nil {
		return page, err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return page, err
		}
		key, ok := tok.(string)
		if !ok {
			return page, errMalformedPage
		}
		switch key {
		case "transactions":
			match, err := decodeResults(dec, sender)
			if err != nil || match != nil {
				page.match = match
				return page, err
			}
		case "next-token":
			var next nextTokenText
			if err := dec.Decode(&next); err != nil {
				return page, err
			}
			page.next = string(next)
		default:
			if err := dec.Decode(&skipValue{}); err != nil {
				return page, err
			}
		}
	}
	return page, expectDelim(dec, '}')
}

// decodeResults reads the transactions array.
func decodeResults(dec *json.Decoder, sender string) (*indexerTxn, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil
	}
	if tok != json.Delim('[') {
		return nil, errMalformedPage
	}
	for n := 0; dec.More(); n++ {
		if n == lookupPageSize {
			return nil, errTooManyResults
		}
		var txn indexerTxn
		if err := dec.Decode(&txn); err != nil {
			return nil, err
		}
		if string(txn.Sender) == sender && txn.RekeyTo != "" {
			return &txn, nil
		}
	}
	return nil, expectDelim(dec, ']')
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != want {
		return errMalformedPage
	}
	return nil
}

// skipValue scans past a value without keeping it: the decoder hands
// UnmarshalJSON a slice of its own buffer.
type skipValue struct{}

func (*skipValue) UnmarshalJSON([]byte) error { return nil }

// presence records whether a field holds anything: any value but null, an
// empty string, an empty object or an empty array. Its content is not kept.
type presence bool

func (p *presence) UnmarshalJSON(raw []byte) error {
	switch string(bytes.TrimSpace(raw)) {
	case "null", `""`, "{}", "[]":
		*p = false
	default:
		*p = true
	}
	return nil
}

type txIDText string

func (t *txIDText) UnmarshalJSON(raw []byte) error {
	s, err := boundedString(raw, txIDLength)
	*t = txIDText(s)
	return err
}

type addressText string

func (a *addressText) UnmarshalJSON(raw []byte) error {
	s, err := boundedString(raw, addressLength)
	*a = addressText(s)
	return err
}

type nextTokenText string

func (n *nextTokenText) UnmarshalJSON(raw []byte) error {
	s, err := boundedString(raw, maxNextTokenLength)
	*n = nextTokenText(s)
	return err
}

type hashBytes []byte

func (h *hashBytes) UnmarshalJSON(raw []byte) error {
	b, err := boundedBase64(raw, genesisHashBytes)
	*h = b
	return err
}

type programBytes []byte

func (p *programBytes) UnmarshalJSON(raw []byte) error {
	b, err := boundedBase64(raw, maxLogicBytes)
	*p = b
	return err
}

// boundedString decodes a JSON string of at most max characters, refusing a
// longer one by its raw length, before anything is allocated. An escaped
// form longer than max is refused too; the Indexer never escapes these.
func boundedString(raw []byte, max int) (string, error) {
	if string(raw) == "null" {
		return "", nil
	}
	if len(raw) < 2 || raw[0] != '"' {
		return "", errFieldNotAString
	}
	if len(raw)-2 > max {
		return "", fmt.Errorf("%w: %d bytes, at most %d", errFieldTooLong, len(raw)-2, max)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

// boundedBase64 decodes a JSON string of standard base64 holding at most
// maxBytes bytes, refusing a longer one by its raw length first and, since
// padding lets a few more bytes share that length, by its decoded length.
func boundedBase64(raw []byte, maxBytes int) ([]byte, error) {
	s, err := boundedString(raw, base64.StdEncoding.EncodedLen(maxBytes))
	if err != nil || s == "" {
		return nil, err
	}
	out := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
	n, err := base64.StdEncoding.Decode(out, []byte(s))
	if err != nil {
		return nil, err
	}
	if n > maxBytes {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", errFieldTooLong, n, maxBytes)
	}
	return out[:n], nil
}
