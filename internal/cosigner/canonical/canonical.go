// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package canonical decodes and validates the canonical TX-prefixed group
// transport used by component signing. It is pure Go (no signature crypto,
// no Falcon libraries) so client binaries can canonicalize groups without
// linking CGo; component signature verification lives in
// internal/sigconstruction/verify.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/txnutil"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const GroupHashDomainV1 = "APLANE_GROUP_V1"

type Txn struct {
	Index int
	Raw   []byte
	Txn   types.Transaction
	TxID  [32]byte
}

type Group struct {
	Entries   []Txn
	GroupHash [32]byte
	GroupID   types.Digest
}

// GroupHash computes SHA-256 over the exact TX-prefixed transport bytes.
func GroupHash(txPrefixed [][]byte) ([32]byte, error) {
	var out [32]byte
	if len(txPrefixed) == 0 {
		return out, fmt.Errorf("group is empty")
	}
	if len(txPrefixed) > types.MaxTxGroupSize {
		return out, fmt.Errorf("group size %d exceeds max %d", len(txPrefixed), types.MaxTxGroupSize)
	}

	h := sha256.New()
	h.Write([]byte(GroupHashDomainV1))
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(txPrefixed)))
	h.Write(count[:])
	for i, raw := range txPrefixed {
		if len(raw) > int(^uint32(0)) {
			return out, fmt.Errorf("transaction %d too large", i)
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(raw)))
		h.Write(lenBuf[:])
		h.Write(raw)
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// DecodeGroupHex decodes TX-prefixed transaction bytes, rejects
// non-canonical msgpack encodings, checks group consistency, and returns the
// off-chain group hash used for audit.
func DecodeGroupHex(groupBytesHex []string) (*Group, error) {
	if len(groupBytesHex) == 0 {
		return nil, fmt.Errorf("group_bytes_hex is empty")
	}
	if len(groupBytesHex) > types.MaxTxGroupSize {
		return nil, fmt.Errorf("group_bytes_hex length %d exceeds max %d", len(groupBytesHex), types.MaxTxGroupSize)
	}

	entries := make([]Txn, len(groupBytesHex))
	raws := make([][]byte, len(groupBytesHex))
	txns := make([]types.Transaction, len(groupBytesHex))
	for i, rawHex := range groupBytesHex {
		raw, err := hex.DecodeString(rawHex)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: invalid hex: %w", i, err)
		}
		txn, err := DecodeTXPrefixed(raw)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: %w", i, err)
		}
		txid := sha512.Sum512_256(raw)
		entries[i] = Txn{
			Index: i,
			Raw:   append([]byte(nil), raw...),
			Txn:   txn,
			TxID:  txid,
		}
		raws[i] = raw
		txns[i] = txn
	}

	groupID, err := ValidateGroupConsistency(txns)
	if err != nil {
		return nil, err
	}
	groupHash, err := GroupHash(raws)
	if err != nil {
		return nil, err
	}
	return &Group{
		Entries:   entries,
		GroupHash: groupHash,
		GroupID:   groupID,
	}, nil
}

// The ways transaction bytes fail the canonical decoders. Each has fixed
// text, so every endpoint that answers a client with one says the same thing.
var (
	ErrMissingTXPrefix = errors.New("missing TX prefix")
	ErrInvalidMsgpack  = errors.New("invalid msgpack")
	ErrNotCanonical    = errors.New("transaction bytes are not canonical")
)

// DecodeError is a codec failure. Its text is ErrInvalidMsgpack's: the
// codec's own wording names its internals, changes with the library, and
// quotes bytes from the input, so it is not fit to send to a client or print
// raw. Detail holds it for a log line that escapes it first.
type DecodeError struct {
	Detail error
}

func (e *DecodeError) Error() string { return ErrInvalidMsgpack.Error() }
func (e *DecodeError) Unwrap() error { return ErrInvalidMsgpack }

// DecodeTXPrefixed decodes one TX-prefixed transaction and rejects any
// encoding that does not re-encode to exactly the same bytes: trailing data,
// non-canonical key order or explicit zero values. It checks nothing about
// the transaction's group; DecodeGroupHex does that for a complete group.
func DecodeTXPrefixed(raw []byte) (types.Transaction, error) {
	var txn types.Transaction
	if len(raw) < 2 || raw[0] != 'T' || raw[1] != 'X' {
		return txn, ErrMissingTXPrefix
	}
	if err := msgpack.Decode(raw[2:], &txn); err != nil {
		return txn, &DecodeError{Detail: err}
	}
	canonical := txnutil.EncodeWithPrefix(txn)
	if !bytes.Equal(raw, canonical) {
		return txn, ErrNotCanonical
	}
	return txn, nil
}

// DecodeSignedTxn decodes one signed transaction and rejects any encoding
// that does not re-encode to exactly the same bytes. Signed bytes that are
// forwarded as given have to be exactly what was decoded and reviewed.
func DecodeSignedTxn(raw []byte) (types.SignedTxn, error) {
	var stxn types.SignedTxn
	if err := msgpack.Decode(raw, &stxn); err != nil {
		return stxn, &DecodeError{Detail: err}
	}
	if !bytes.Equal(msgpack.Encode(stxn), raw) {
		return stxn, ErrNotCanonical
	}
	return stxn, nil
}

// ValidateGroupConsistency checks the MVP pre-grouped transaction invariant.
func ValidateGroupConsistency(txns []types.Transaction) (types.Digest, error) {
	var empty types.Digest
	if len(txns) == 0 {
		return empty, fmt.Errorf("group is empty")
	}
	if len(txns) == 1 {
		if txns[0].Group != empty {
			return empty, fmt.Errorf("singleton transaction must not have a group ID")
		}
		return empty, nil
	}

	groupID := txns[0].Group
	if groupID == empty {
		return empty, fmt.Errorf("group transaction 0 has empty group ID")
	}
	for i := 1; i < len(txns); i++ {
		if txns[i].Group == empty {
			return empty, fmt.Errorf("group transaction %d has empty group ID", i)
		}
		if txns[i].Group != groupID {
			return empty, fmt.Errorf("group transaction %d has divergent group ID", i)
		}
	}

	cleared := append([]types.Transaction(nil), txns...)
	for i := range cleared {
		cleared[i].Group = empty
	}
	computed, err := algocrypto.ComputeGroupID(cleared)
	if err != nil {
		return empty, fmt.Errorf("compute group ID: %w", err)
	}
	if computed != groupID {
		return empty, fmt.Errorf("group ID does not match decoded transactions")
	}
	return groupID, nil
}
