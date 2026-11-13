// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"errors"
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/engine"
)

// ErrLsigArgsWithoutTransactions refuses a plugin command given arg: words
// whose first result has no transactions: the words apply to the first
// result only, so they would reach nothing.
var ErrLsigArgsWithoutTransactions = errors.New("arg: values were given, but the plugin's first result has no transactions to give them to; run the command without its arg: words")

// resolveLsigArgs turns a command's arg: words into the arguments the engine
// places: the untargeted ones, for every transaction, and one map per sending
// account. Every command that signs resolves its words here, once, before
// anything is sent.
//
// senders are the accounts the command was asked to send from, as addresses,
// with any set expanded: for a set command, every account in the list, sent
// from or skipped. A word's target is resolved to an address as the command's
// own account references are, and the word is refused when:
//   - its target is not one of senders: it would reach no transaction;
//   - it gives a name another word already gives the same account, however
//     the two are written (an alias and its address, two aliases for one
//     account), or another untargeted word already gives;
//   - it gives a name for an account that an untargeted word also gives,
//     which reaches that account too.
//
// There is no "more specific wins": every transaction gets each name at most
// once. Which names a key takes is not looked up; the signer judges that.
func (a *App) resolveLsigArgs(args cmdspec.LsigArgs, senders []string) (engine.LsigArgs, error) {
	if len(args) == 0 {
		return engine.LsigArgs{}, nil
	}
	sending := make(map[string]bool, len(senders))
	for _, sender := range senders {
		sending[sender] = true
	}
	resolver := a.eng.NewAddressResolver()

	// Each word's target is resolved to an address ("" for an untargeted
	// word); a name may be given once per resolved target. accounts is how
	// messages name each word's account.
	accounts := make([]string, len(args))
	words := make(map[string]map[string]string) // target -> name -> word
	values := make(map[string]map[string][]byte)
	for i, arg := range args {
		target, account := "", "every transaction"
		if !arg.Untargeted() {
			address, err := resolver.ResolveSingle(arg.Target)
			if err != nil {
				return engine.LsigArgs{}, fmt.Errorf("%s: %w", arg.Word(), err)
			}
			target, account = address, address
			if arg.Target != address {
				account = fmt.Sprintf("%s (%s)", arg.Target, address)
			}
			if !sending[address] {
				return engine.LsigArgs{}, fmt.Errorf("%s: %s is not one of the accounts this command sends from; name a sending account, or leave the account out for every transaction", arg.Word(), account)
			}
		}
		if words[target] == nil {
			words[target] = make(map[string]string)
			values[target] = make(map[string][]byte)
		}
		if word, repeated := words[target][arg.Name]; repeated {
			return engine.LsigArgs{}, fmt.Errorf("%s and %s both give %s to %s; give it once", word, arg.Word(), arg.Name, account)
		}
		accounts[i] = account
		words[target][arg.Name] = arg.Word()
		values[target][arg.Name] = arg.Value
	}

	for i, arg := range args {
		if arg.Untargeted() {
			continue
		}
		if word, both := words[""][arg.Name]; both {
			return engine.LsigArgs{}, fmt.Errorf("%s and %s both give %s to %s: %s, with no account, gives it to every transaction already; give it either with no account or for each account that takes it", word, arg.Word(), arg.Name, accounts[i], word)
		}
	}
	untargeted := values[""]
	delete(values, "")
	return engine.NewLsigArgs(untargeted, values), nil
}

// untargetedLsigArgs is the JS API's lsigArgs option as arg: words: each name
// untargeted, for every transaction, in name order.
func untargetedLsigArgs(args map[string][]byte) cmdspec.LsigArgs {
	if len(args) == 0 {
		return nil
	}
	names := make([]string, 0, len(args))
	for name := range args {
		names = append(names, name)
	}
	sort.Strings(names)
	words := make(cmdspec.LsigArgs, len(names))
	for i, name := range names {
		words[i] = cmdspec.LsigArg{Name: name, Value: args[name]}
	}
	return words
}
