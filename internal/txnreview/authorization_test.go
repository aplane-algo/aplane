// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestAuthorization(t *testing.T) {
	sender, rekeyed := types.Address{1}, types.Address{2}
	program := []byte{0x06, 0x81, 0x01}
	programAddress := crypto.AddressFromProgram(program)
	msig := types.MultisigSig{Version: 1, Threshold: 2, Subsigs: make([]types.MultisigSubsig, 3)}
	msigAccount, err := crypto.MultisigAccountFromSig(msig)
	if err != nil {
		t.Fatal(err)
	}
	msigAddress, err := msigAccount.Address()
	if err != nil {
		t.Fatal(err)
	}
	signed := func(fill func(*types.SignedTxn)) types.SignedTxn {
		stxn := types.SignedTxn{Txn: types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: sender}}}
		fill(&stxn)
		return stxn
	}
	for _, tc := range []struct {
		name string
		stxn types.SignedTxn
		want string
	}{
		{"single", signed(func(s *types.SignedTxn) { s.Sig = types.Signature{9} }),
			sender.String() + " (single signature, not verified here)"},
		{"rekeyed", signed(func(s *types.SignedTxn) { s.Sig = types.Signature{9}; s.AuthAddr = rekeyed }),
			rekeyed.String() + " (single signature, named as the sender's authorizer, not verified here)"},
		{"auth address is the sender", signed(func(s *types.SignedTxn) { s.Sig = types.Signature{9}; s.AuthAddr = sender }),
			sender.String() + " (single signature, not verified here)"},
		{"multisig", signed(func(s *types.SignedTxn) { s.Msig = msig; s.Txn.Sender = msigAddress }),
			msigAddress.String() + " (multisig, 2 of 3, not verified here)"},
		{"multisig of another address", signed(func(s *types.SignedTxn) { s.Msig = msig }),
			sender.String() + " (multisig, 2 of 3, whose address is " + msigAddress.String() + ", not verified here)"},
		{"multisig named as the authorizer", signed(func(s *types.SignedTxn) { s.Msig = msig; s.AuthAddr = msigAddress }),
			msigAddress.String() + " (multisig, 2 of 3, named as the sender's authorizer, not verified here)"},
		{"multisig with no address", signed(func(s *types.SignedTxn) {
			s.Msig = types.MultisigSig{Version: 1, Threshold: 4, Subsigs: make([]types.MultisigSubsig, 3)}
		}), sender.String() + " (multisig, 4 of 3, whose address cannot be computed: invalid threshold, not verified here)"},
		{"native PQ", signed(func(s *types.SignedTxn) { s.PQsig = types.PQSig{Scheme: types.PQSchemeFalcon1024} }),
			sender.String() + " (native post-quantum signature, not verified here)"},
		{"LogicSig account", signed(func(s *types.SignedTxn) {
			s.Lsig = types.LogicSig{Logic: program}
			s.Txn.Sender = programAddress
		}), programAddress.String() + " (LogicSig account, not verified here)"},
		{"LogicSig of another address", signed(func(s *types.SignedTxn) { s.Lsig = types.LogicSig{Logic: program} }),
			sender.String() + " (LogicSig whose program address is " + programAddress.String() + ", not verified here)"},
		{"delegated by a signature", signed(func(s *types.SignedTxn) { s.Lsig = types.LogicSig{Logic: program, Sig: types.Signature{9}} }),
			sender.String() + " (LogicSig delegated by a single signature, not verified here)"},
		{"delegated by a multisig", signed(func(s *types.SignedTxn) {
			s.Lsig = types.LogicSig{Logic: program, Msig: msig}
			s.Txn.Sender = msigAddress
		}), msigAddress.String() + " (LogicSig delegated by multisig, 2 of 3, not verified here)"},
		{"delegated by an lmsig", signed(func(s *types.SignedTxn) {
			s.Lsig = types.LogicSig{Logic: program, LMsig: msig}
			s.Txn.Sender = msigAddress
		}), msigAddress.String() + " (LogicSig delegated by multisig, 2 of 3, not verified here)"},
		{"delegated by another address's multisig", signed(func(s *types.SignedTxn) { s.Lsig = types.LogicSig{Logic: program, LMsig: msig} }),
			sender.String() + " (LogicSig delegated by multisig, 2 of 3, whose address is " + msigAddress.String() + ", not verified here)"},
		{"delegated twice", signed(func(s *types.SignedTxn) {
			s.Lsig = types.LogicSig{Logic: program, Sig: types.Signature{9}, Msig: msig}
			s.Txn.Sender = msigAddress
		}), msigAddress.String() + " (MALFORMED LogicSig, more than one delegation: a single signature; multisig, 2 of 3, not verified here)"},
		{"delegated by a PQ signature", signed(func(s *types.SignedTxn) {
			s.Lsig = types.LogicSig{Logic: program, PQsig: types.PQSig{Scheme: types.PQSchemeFalcon1024}}
		}), sender.String() + " (LogicSig delegated by a native post-quantum signature, not verified here)"},
		{"none", signed(func(*types.SignedTxn) {}),
			sender.String() + " (NO SIGNATURE, not verified here)"},
	} {
		if got := Authorization(tc.stxn); got != tc.want {
			t.Errorf("%s: Authorization() = %q, want %q", tc.name, got, tc.want)
		}
	}

	both := signed(func(s *types.SignedTxn) { s.Sig = types.Signature{9}; s.Msig = msig })
	if got := Authorization(both); !strings.Contains(got, "MALFORMED, more than one kind: single signature; multisig, 2 of 3") {
		t.Errorf("two kinds: Authorization() = %q", got)
	}
}

// The addresses an envelope names in its authorization are its auth address
// and every multisig subsignature key, its own and its LogicSig's, once each,
// whether or not a subsignature is filled in.
func TestAuthorizationAddresses(t *testing.T) {
	sender, authorizer := types.Address{1}, types.Address{2}
	a, b, c := crypto.GenerateAccount(), crypto.GenerateAccount(), crypto.GenerateAccount()
	msig := func(accounts ...crypto.Account) types.MultisigSig {
		subsigs := make([]types.MultisigSubsig, len(accounts))
		for i, account := range accounts {
			subsigs[i] = types.MultisigSubsig{Key: account.PublicKey}
		}
		subsigs[0].Sig = types.Signature{9}
		return types.MultisigSig{Version: 1, Threshold: 1, Subsigs: subsigs}
	}
	program := []byte{0x06, 0x81, 0x01}
	for _, tc := range []struct {
		name string
		stxn types.SignedTxn
		want []types.Address
	}{
		{"single signature by the sender", types.SignedTxn{Sig: types.Signature{9}}, nil},
		{"named authorizer", types.SignedTxn{Sig: types.Signature{9}, AuthAddr: authorizer}, []types.Address{authorizer}},
		{"multisig", types.SignedTxn{Msig: msig(a, b)}, []types.Address{a.Address, b.Address}},
		{"multisig named as the authorizer, a key repeated", types.SignedTxn{Msig: msig(a, b, a), AuthAddr: authorizer},
			[]types.Address{authorizer, a.Address, b.Address}},
		{"LogicSig account", types.SignedTxn{Lsig: types.LogicSig{Logic: program}}, nil},
		{"LogicSig delegated by a multisig", types.SignedTxn{Lsig: types.LogicSig{Logic: program, Msig: msig(b, c)}}, []types.Address{b.Address, c.Address}},
		{"LogicSig delegated by an lmsig", types.SignedTxn{Lsig: types.LogicSig{Logic: program, LMsig: msig(c)}}, []types.Address{c.Address}},
		{"multisig keys that are not 32 bytes name no address", types.SignedTxn{Msig: types.MultisigSig{Version: 1, Threshold: 1, Subsigs: []types.MultisigSubsig{
			{Key: a.PublicKey[:31]}, {Key: append(append([]byte{}, a.PublicKey...), 7)}, {Key: b.PublicKey},
		}}}, []types.Address{b.Address}},
	} {
		tc.stxn.Txn = types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: sender}}
		if got := AuthorizationAddresses(tc.stxn); !slices.Equal(got, tc.want) {
			t.Errorf("%s: AuthorizationAddresses() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
