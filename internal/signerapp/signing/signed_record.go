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
// does when it signs them, and whose group ID the planner set; dummyCount
// is how many trailing ones are dummies this request added and signed (none
// for a frozen group, whose dummies the client signs).
func signedGroupOf(txns []types.Transaction, dummyCount int) signedGroup {
	txIDs := make([]string, len(txns))
	for i, txn := range txns {
		txIDs[i] = algocrypto.GetTxID(txn)
	}
	var groupID types.Digest
	if len(txns) > 0 {
		groupID = txns[0].Group
	}
	return newSignedGroup(txns, txIDs, groupID, dummyCount)
}

// decodedSignedGroup describes a group signed as the client sent it, with
// the IDs computed from its bytes at decode, the IDs that were signed, and
// the group ID its decode validated every transaction carries.
func decodedSignedGroup(group *canonical.Group, dummyCount int) signedGroup {
	if group == nil {
		return signedGroup{}
	}
	txns := make([]types.Transaction, len(group.Entries))
	txIDs := make([]string, len(group.Entries))
	for i, entry := range group.Entries {
		txns[i] = entry.Txn
		txIDs[i] = txIDString(entry.TxID)
	}
	return newSignedGroup(txns, txIDs, group.GroupID, dummyCount)
}

// txIDString is a transaction ID in the text form Algorand writes it in:
// unpadded base32.
func txIDString(id [32]byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:])
}

// newSignedGroup records groupID only when the transactions were signed in
// a group; a transaction signed alone has none.
func newSignedGroup(txns []types.Transaction, txIDs []string, groupID types.Digest, dummyCount int) signedGroup {
	g := signedGroup{txns: txns, txIDs: txIDs, dummyCount: dummyCount}
	if groupID != (types.Digest{}) {
		g.groupID = base64.StdEncoding.EncodeToString(groupID[:])
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
