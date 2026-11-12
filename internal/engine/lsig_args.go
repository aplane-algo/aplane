// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// LogicSig argument placement. A command takes one set of LogicSig arguments
// (apshell's arg:name=value, JavaScript's lsigArgs) for everything it signs.
// placeLsigArgs is the one place that decides which position gets which of
// them and which are refused. Every signing path reaches it: checkReadyToSign
// for shell commands, scripts, transaction files and the default plugin flow,
// SignAndSubmitWithPluginSigners for a presign-plan group, CheckPluginLsigArgs
// for the plugin review, and LsigArgsForItems for a command that makes one
// submission per item. Nothing above the engine filters or checks them.

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
)

// LsigArgs is the LogicSig arguments given once for a submission: names and
// values as typed, before any position has been given them. placeLsigArgs
// alone gives them out. The zero value is no arguments.
type LsigArgs struct {
	values map[string][]byte
	// forItems marks arguments LsigArgsForItems checked against every item of
	// a command that makes one submission per item. Each item's submission
	// then gives its position what the position's key declares and refuses no
	// name, since every name was found declared by some item's key.
	forItems bool
}

// NewLsigArgs is the arguments given for one submission. A name no signing
// key of the submission declares is refused when it is signed.
func NewLsigArgs(values map[string][]byte) LsigArgs {
	return LsigArgs{values: values}
}

// Values returns a copy of the names and values as given.
func (a LsigArgs) Values() map[string][]byte {
	if len(a.values) == 0 {
		return nil
	}
	return maps.Clone(a.values)
}

// Len is the number of names given.
func (a LsigArgs) Len() int { return len(a.values) }

// UndeclaredLsigArgsError refuses LogicSig argument names that no signing key
// of a submission declares: given to no position, they would be sent nowhere.
// Names and Declared, the names those keys do declare, are sorted.
type UndeclaredLsigArgsError struct {
	Names    []string
	Declared []string
}

func (e *UndeclaredLsigArgsError) Error() string {
	noun := "argument"
	if len(e.Names) > 1 {
		noun = "arguments"
	}
	declared := "no arguments"
	if len(e.Declared) > 0 {
		declared = quotedList(e.Declared)
	}
	return fmt.Sprintf("no signing key here declares the LogicSig %s %s; they declare %s", noun, quotedList(e.Names), declared)
}

func quotedList(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = strconv.Quote(name)
	}
	return strings.Join(quoted, ", ")
}

// CheckPluginLsigArgs is the plugin group check's run of the placement that
// signing makes, over the decoded group. A position whose sender is in
// pluginOwned is signed by the plugin: it gets nothing and declares nothing.
// It refuses what submission would refuse, before the group is shown, and
// returns nothing else; SubmitPluginTransactions places the same arguments
// again on the same group. With no arguments given there is nothing to
// check, and nothing is fetched.
func (e *Engine) CheckPluginLsigArgs(ctx context.Context, txns []types.Transaction, pluginOwned map[string]string, values map[string][]byte) error {
	if len(values) == 0 {
		return nil
	}
	if !e.IsConnected() {
		return ErrNotConnected
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := e.lsigArgsForGroup(ctx, txns, pluginOwned, NewLsigArgs(values))
	return err
}

// LsigArgsForItems checks LogicSig arguments given once for a command that
// makes one submission per item: send, sweep or validate over several
// accounts. itemSenders holds each item's sender. With more than one item,
// every name must be declared by the signing key of some item's account, as
// the cache resolves it, or it is refused here, before anything is sent; the
// key list is fetched again once first when a name is unknown, since the
// cache may be stale. Each item then gets what its own key declares, and an
// item whose key declares none of the names gets none: that is not an error.
// With one item, the command is one submission, which refuses a name its key
// does not declare when it is signed.
func (e *Engine) LsigArgsForItems(ctx context.Context, itemSenders []string, values map[string][]byte) (LsigArgs, error) {
	args := NewLsigArgs(values)
	if len(values) == 0 || len(itemSenders) <= 1 {
		return args, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := e.lsigArgSchemas(ctx, itemSenders, values, true, false); err != nil {
		return LsigArgs{}, err
	}
	args.forItems = true
	return args, nil
}

// lsigArgsForGroup is the precondition signing shares for LogicSig arguments
// over a group: it fetches what the client lacks to know each position's
// signing key (refreshSubmitSigningState), then places the arguments
// (placeLsigArgs). A position whose sender is in pluginOwned is signed by a
// plugin, not by apsigner, and takes part in neither.
func (e *Engine) lsigArgsForGroup(ctx context.Context, txns []types.Transaction, pluginOwned map[string]string, args LsigArgs) ([]map[string][]byte, error) {
	senders := make([]string, len(txns))
	managed := make([]types.Transaction, 0, len(txns))
	for i, txn := range txns {
		sender := txn.Sender.String()
		if _, owned := pluginOwned[sender]; owned {
			continue
		}
		senders[i] = sender
		managed = append(managed, txn)
	}
	keysFresh, err := e.refreshSubmitSigningState(ctx, managed)
	if err != nil {
		return nil, err
	}
	return e.placeLsigArgs(ctx, senders, args, keysFresh)
}

// placeLsigArgs gives each position of a submission the LogicSig arguments
// its signing key declares, and refuses what cannot be signed. senders holds
// each position's sender, or "" for a position apsigner does not sign, which
// gets nothing and declares nothing. The signing key is the sender's
// effective signer (its auth address when rekeyed), as the cache resolves
// it: a native key (ed25519 or native Falcon) declares no arguments and is
// given none. A name no position declares is refused (lsigArgSchemas), unless
// LsigArgsForItems has already found it declared across the items of a set.
// Each position is then checked against its key's declarations: a required
// argument left out, or a value of the wrong declared length, is refused.
// keysFresh says the key list was fetched for this submission already, so a
// name it does not declare is refused without fetching it again.
func (e *Engine) placeLsigArgs(ctx context.Context, senders []string, args LsigArgs, keysFresh bool) ([]map[string][]byte, error) {
	schemas, err := e.lsigArgSchemas(ctx, senders, args.values, !args.forItems, keysFresh)
	if err != nil {
		return nil, err
	}
	placed := make([]map[string][]byte, len(senders))
	for i, schema := range schemas {
		var missing []string
		for _, def := range schema {
			value, given := args.values[def.Name]
			if !given {
				if def.Required {
					missing = append(missing, def.Name)
				}
				continue
			}
			if def.ByteLength > 0 && len(value) != def.ByteLength {
				return nil, fmt.Errorf("transaction %d: invalid LogicSig arguments: argument '%s': expected %d bytes, got %d", i+1, def.Name, def.ByteLength, len(value))
			}
			if placed[i] == nil {
				placed[i] = make(map[string][]byte, len(schema))
			}
			placed[i][def.Name] = value
		}
		switch len(missing) {
		case 0:
		case 1:
			return nil, fmt.Errorf("transaction %d: invalid LogicSig arguments: missing required argument: %s", i+1, missing[0])
		default:
			return nil, fmt.Errorf("transaction %d: invalid LogicSig arguments: missing required arguments: %s", i+1, strings.Join(missing, ", "))
		}
	}
	return placed, nil
}

// lsigArgSchemas returns the arguments each position's signing key declares,
// from the signer cache. When refuse is set, a given name that none of them
// declares is refused with an *UndeclaredLsigArgsError; the cached key list
// may be stale, so unless keysFresh says it was just fetched, it is fetched
// once and the names are looked up again before anything is refused.
func (e *Engine) lsigArgSchemas(ctx context.Context, senders []string, values map[string][]byte, refuse, keysFresh bool) ([][]cache.SigningArgInfo, error) {
	schemas := e.signerCacheSigningArgsFor(e.positionSigners(senders))
	if !refuse || len(values) == 0 {
		return schemas, nil
	}
	undeclared := undeclaredLsigArgs(schemas, values)
	if undeclared == nil {
		return schemas, nil
	}
	if !keysFresh {
		if _, err := e.RefreshKeys(ctx); err != nil {
			return nil, fmt.Errorf("%w (in the cached key list; fetching the signer's key list to look again failed: %v)", undeclared, err)
		}
		schemas = e.signerCacheSigningArgsFor(e.positionSigners(senders))
		undeclared = undeclaredLsigArgs(schemas, values)
	}
	if undeclared != nil {
		return nil, undeclared
	}
	return schemas, nil
}

// positionSigners resolves each position's sender to its effective signer,
// keeping "" for a position apsigner does not sign.
func (e *Core) positionSigners(senders []string) []string {
	signers := make([]string, len(senders))
	for i, sender := range senders {
		if sender != "" {
			signers[i] = e.AuthCache.ResolveEffectiveSigner(sender)
		}
	}
	return signers
}

// undeclaredLsigArgs refuses the given names no schema declares, or returns
// nil when every name is declared.
func undeclaredLsigArgs(schemas [][]cache.SigningArgInfo, values map[string][]byte) *UndeclaredLsigArgsError {
	declared := make(map[string]bool)
	for _, schema := range schemas {
		for _, def := range schema {
			declared[def.Name] = true
		}
	}
	var names []string
	for name := range values {
		if !declared[name] {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	declaredNames := make([]string, 0, len(declared))
	for name := range declared {
		declaredNames = append(declaredNames, name)
	}
	sort.Strings(declaredNames)
	return &UndeclaredLsigArgsError{Names: names, Declared: declaredNames}
}
