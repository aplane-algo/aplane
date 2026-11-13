// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"fmt"
	"maps"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// LsigArgs is the LogicSig arguments one submission was given, addressed by
// the account that sends a transaction: some untargeted, for every
// transaction, and some for one sending account each. A transaction gets the
// untargeted arguments and those for its sender, and no others. Two
// transactions from one sender get the same arguments. The zero value gives
// none.
//
// Nothing can hand the engine a bare map of arguments: a caller says whom
// they are for, with UntargetedLsigArgs or NewLsigArgs. apshellapp builds the
// value from a command's arg: words, having resolved each target to an
// address and refused a target the command does not send from and a name
// given twice to one transaction; the JS API's lsigArgs option is
// UntargetedLsigArgs. The engine judges nothing in it: it places it.
//
// A value is never changed once made: its constructors copy what they are
// given and For returns a new map.
type LsigArgs struct {
	untargeted map[string][]byte
	bySender   map[string]map[string][]byte
}

// UntargetedLsigArgs addresses args to every transaction of the submission.
func UntargetedLsigArgs(args map[string][]byte) LsigArgs {
	return NewLsigArgs(args, nil)
}

// NewLsigArgs addresses untargeted to every transaction of the submission and
// each map in bySender to the transactions sent by the account it is keyed by
// (an address). The caller has refused a name given both untargeted and for
// an account, so no transaction is given one name twice. The maps are copied;
// empty ones are dropped.
func NewLsigArgs(untargeted map[string][]byte, bySender map[string]map[string][]byte) LsigArgs {
	var args LsigArgs
	if len(untargeted) > 0 {
		args.untargeted = cloneLsigArgMap(untargeted)
	}
	for sender, named := range bySender {
		if len(named) == 0 {
			continue
		}
		if args.bySender == nil {
			args.bySender = make(map[string]map[string][]byte, len(bySender))
		}
		args.bySender[sender] = cloneLsigArgMap(named)
	}
	return args
}

// Empty reports whether no transaction gets an argument.
func (a LsigArgs) Empty() bool {
	return len(a.untargeted) == 0 && len(a.bySender) == 0
}

// For returns the arguments a transaction sent by sender gets: the
// untargeted ones and those for sender, in a new map, or nil when it gets
// none.
func (a LsigArgs) For(sender string) map[string][]byte {
	named := a.bySender[sender]
	if len(a.untargeted) == 0 && len(named) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(a.untargeted)+len(named))
	for name, value := range a.untargeted {
		out[name] = append([]byte(nil), value...)
	}
	for name, value := range named {
		out[name] = append([]byte(nil), value...)
	}
	return out
}

// place gives each transaction its sender's arguments (For), in transaction
// order. It is nil when no transaction gets any, as a submission without
// arguments has always been.
func (a LsigArgs) place(txns []types.Transaction) []map[string][]byte {
	if a.Empty() {
		return nil
	}
	placed := make([]map[string][]byte, len(txns))
	for i, txn := range txns {
		placed[i] = a.For(txn.Sender.String())
	}
	return placed
}

// refusePluginSignedLsigArgs refuses a presign-plan group in which a
// plugin-signed position gets an argument, untargeted or addressed to its
// sender: the plugin is asked to sign its positions with no arguments (a
// PluginSlotSignRequest has no field for them), so an argument placed there
// would be dropped. placed is the group's placement; positions are named from
// one, as the command's input is.
func refusePluginSignedLsigArgs(txns []types.Transaction, placed []map[string][]byte, pluginSignerRefs map[string]string) error {
	for i, txn := range txns {
		if i >= len(placed) || len(placed[i]) == 0 {
			continue
		}
		sender := txn.Sender.String()
		if _, owned := pluginSignerRefs[sender]; owned {
			return fmt.Errorf("transaction %d: LogicSig arguments reach %s, which the plugin signs: a plugin-signed transaction takes no arguments; give each argument a target, an account apsigner signs for (arg:<account>:<name>=<value>)", i+1, sender)
		}
	}
	return nil
}

func cloneLsigArgMap(args map[string][]byte) map[string][]byte {
	out := maps.Clone(args)
	for name, value := range out {
		out[name] = append([]byte(nil), value...)
	}
	return out
}
