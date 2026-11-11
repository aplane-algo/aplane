// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base32"
	"encoding/base64"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// SignedRecord is the audit record of one transaction this signer signed: the
// transaction as signed, after planning raised its fee, set its group ID and
// added dummies, and the group it was signed in. It never holds key material,
// signatures or LogicSig argument values.
type SignedRecord struct {
	// AuthAddress is the signing key's address, or a cosigner's Witness Key ID.
	AuthAddress  string
	TxnSender    string
	Details      string
	PolicyRuleID string
	TxID         string
	// Fee is the signed transaction's fee, in microAlgos.
	Fee uint64
	// GroupID (base64) and GroupTxIDs, every transaction of the group in
	// order, are empty for a transaction signed alone. The last DummyCount
	// of GroupTxIDs are the dummies this request added and signed.
	GroupID    string
	GroupTxIDs []string
	DummyCount int
}

// signedGroup is what every SignedRecord of one request shares: the final
// group, and how many of its trailing transactions are dummies this request
// signed.
type signedGroup struct {
	txns       []types.Transaction
	txIDs      []string
	groupID    string
	dummyCount int
}

// signedGroupOf describes the final group a request signed. txns are the
// transactions exactly as signed, whose IDs it computes as the executor
// does when it signs them; dummyCount is how many trailing ones are dummies
// this request added and signed (none when the dummies were signed
// elsewhere, as in a frozen group's components).
func signedGroupOf(txns []types.Transaction, dummyCount int) signedGroup {
	txIDs := make([]string, len(txns))
	for i, txn := range txns {
		txIDs[i] = algocrypto.GetTxID(txn)
	}
	return newSignedGroup(txns, txIDs, dummyCount)
}

// decodedSignedGroup describes a group signed as the client sent it, with
// the IDs computed from its bytes at decode: the IDs that were signed.
func decodedSignedGroup(group *canonical.Group, dummyCount int) signedGroup {
	if group == nil {
		return signedGroup{}
	}
	txns := make([]types.Transaction, len(group.Entries))
	txIDs := make([]string, len(group.Entries))
	for i, entry := range group.Entries {
		txns[i] = entry.Txn
		txIDs[i] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entry.TxID[:])
	}
	return newSignedGroup(txns, txIDs, dummyCount)
}

func newSignedGroup(txns []types.Transaction, txIDs []string, dummyCount int) signedGroup {
	g := signedGroup{txns: txns, txIDs: txIDs, dummyCount: dummyCount}
	if len(txns) > 0 && txns[0].Group != (types.Digest{}) {
		g.groupID = base64.StdEncoding.EncodeToString(txns[0].Group[:])
	}
	return g
}

// record is the SignedRecord of the transaction at index, signed by
// authAddress.
func (g signedGroup) record(index int, authAddress, details, policyRuleID string) SignedRecord {
	r := SignedRecord{
		AuthAddress:  authAddress,
		Details:      details,
		PolicyRuleID: policyRuleID,
	}
	if index < 0 || index >= len(g.txns) {
		return r
	}
	txn := g.txns[index]
	r.TxnSender = txn.Sender.String()
	r.TxID = g.txIDs[index]
	r.Fee = uint64(txn.Fee)
	if g.groupID != "" {
		r.GroupID = g.groupID
		r.GroupTxIDs = append([]string(nil), g.txIDs...)
		r.DummyCount = g.dummyCount
	}
	return r
}
