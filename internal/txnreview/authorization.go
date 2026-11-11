// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Authorization says who authorizes a signed transaction and with what kind
// of signature, as its envelope states it: the authorizer is the envelope's
// signer field when it is set, else the sender. Nothing here checks the
// signature or the chain, and the text says so: a reviewer reads a claim,
// which the network accepts or refuses.
func Authorization(stxn types.SignedTxn) string {
	authorizer := stxn.Txn.Sender
	if !stxn.AuthAddr.IsZero() {
		authorizer = stxn.AuthAddr
	}
	parts := []string{signatureKind(stxn, authorizer)}
	if authorizer != stxn.Txn.Sender {
		parts = append(parts, "named as the sender's authorizer")
	}
	parts = append(parts, "not verified here")
	return fmt.Sprintf("%s (%s)", authorizer, strings.Join(parts, ", "))
}

// signatureKind names the one authorization a signed transaction carries. The
// network takes exactly one; none, or more than one, is shown as what it is.
func signatureKind(stxn types.SignedTxn, authorizer types.Address) string {
	var kinds []string
	if stxn.Sig != (types.Signature{}) {
		kinds = append(kinds, "single signature")
	}
	if !stxn.Msig.Blank() {
		kinds = append(kinds, multisigKind(stxn.Msig))
	}
	if !stxn.PQsig.Blank() {
		kinds = append(kinds, "native post-quantum signature")
	}
	if !stxn.Lsig.Blank() {
		kinds = append(kinds, logicSigKind(stxn.Lsig, authorizer))
	}
	switch len(kinds) {
	case 0:
		return "NO SIGNATURE"
	case 1:
		return kinds[0]
	default:
		return "MALFORMED, more than one kind: " + strings.Join(kinds, "; ")
	}
}

func multisigKind(msig types.MultisigSig) string {
	return fmt.Sprintf("multisig, %d of %d", msig.Threshold, len(msig.Subsigs))
}

// logicSigKind names a LogicSig: delegated by the authorizer's own signature,
// or an account of its own, whose address is the program's.
func logicSigKind(lsig types.LogicSig, authorizer types.Address) string {
	switch {
	case lsig.Sig != (types.Signature{}):
		return "LogicSig delegated by a single signature"
	case !lsig.Msig.Blank():
		return "LogicSig delegated by " + multisigKind(lsig.Msig)
	case !lsig.LMsig.Blank():
		return "LogicSig delegated by " + multisigKind(lsig.LMsig)
	case !lsig.PQsig.Blank():
		return "LogicSig delegated by a native post-quantum signature"
	}
	if program := crypto.AddressFromProgram(lsig.Logic); program != authorizer {
		return "LogicSig whose program address is " + program.String()
	}
	return "LogicSig account"
}
