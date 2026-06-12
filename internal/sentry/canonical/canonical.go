// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package canonical decodes and validates the canonical TX-prefixed group
// transport used by component signing. It is pure Go (no signature crypto,
// no Falcon libraries) so client binaries can canonicalize groups without
// linking CGo; component signature verification lives in
// internal/sentry/verify.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
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
		txn, err := decodeCanonicalTXPrefixed(raw)
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

func decodeCanonicalTXPrefixed(raw []byte) (types.Transaction, error) {
	var txn types.Transaction
	if len(raw) < 2 || raw[0] != 'T' || raw[1] != 'X' {
		return txn, fmt.Errorf("missing TX prefix")
	}
	if err := msgpack.Decode(raw[2:], &txn); err != nil {
		return txn, fmt.Errorf("decode transaction: %w", err)
	}
	canonical := txnutil.EncodeWithPrefix(txn)
	if !bytes.Equal(raw, canonical) {
		return txn, fmt.Errorf("transaction bytes are not canonical")
	}
	return txn, nil
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
