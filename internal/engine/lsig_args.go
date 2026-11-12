// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// LogicSig argument placement. A command takes one set of LogicSig arguments
// (apshell's arg:name=value, JavaScript's lsigArgs) for everything it signs.
// placeLsigArgs is the one place that decides which position gets which of
// them and which are refused. Every signing path reaches it: checkReadyToSign
// for shell commands, scripts, transaction files and the default plugin flow,
// SignAndSubmitWithPluginSigners for a presign-plan group given arguments,
// and CheckPluginLsigArgs for the plugin review. LsigArgsForItems checks the
// names once for a command that makes one submission per item, through the
// same resolution and retry (judgeLsigArgs). Nothing above the engine filters
// or checks them.

import (
	"context"
	"errors"
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
	_, err := e.lsigArgsForGroup(ctx, txns, pluginOwned, NewLsigArgs(values))
	return err
}

// LsigArgsForItems checks LogicSig arguments given once for a command that
// makes one submission per item: send, sweep or validate over one account or
// several. itemSenders holds each item's sender. Each item's signing key is
// resolved as its own submission resolves it (judgeLsigArgs), and every name
// must be declared by the key of some item, or it is refused here, before
// anything is sent. Each item's submission then gives its position what its
// own key declares, and an item whose key declares none of the names gets
// none: that is not an error.
//
// An item whose auth address cannot be looked up is set aside: its own
// submission looks it up again and fails on it, as it would without this
// check, and the others go on. Its key is unknown, so a name that only it
// might declare is refused, and the refusal says which accounts could not be
// looked up.
func (e *Engine) LsigArgsForItems(ctx context.Context, itemSenders []string, values map[string][]byte) (LsigArgs, error) {
	args := NewLsigArgs(values)
	if len(values) == 0 {
		return args, nil
	}
	setAside := make(map[string]error)
	err := e.judgeLsigArgs(ctx, itemSenders, setAside, func(signers []string) error {
		if undeclared := undeclaredLsigArgs(e.signerCacheSigningArgsFor(signers), values); undeclared != nil {
			return undeclared
		}
		return nil
	})
	if err != nil {
		var undeclared *UndeclaredLsigArgsError
		if errors.As(err, &undeclared) && len(setAside) > 0 {
			err = fmt.Errorf("%w; %s", err, notLookedUp(setAside))
		}
		return LsigArgs{}, err
	}
	args.forItems = true
	return args, nil
}

// notLookedUp says which accounts LsigArgsForItems set aside, and why.
func notLookedUp(setAside map[string]error) string {
	senders := make([]string, 0, len(setAside))
	for sender := range setAside {
		senders = append(senders, sender)
	}
	sort.Strings(senders)
	reasons := make([]string, len(senders))
	for i, sender := range senders {
		reasons[i] = setAside[sender].Error()
	}
	noun := "account"
	if len(senders) > 1 {
		noun = "accounts"
	}
	return fmt.Sprintf("%d %s could not be looked up, so their keys were not checked (%s)", len(senders), noun, strings.Join(reasons, "; "))
}

// lsigArgsForGroup places the LogicSig arguments given for a group, a
// submission (placeLsigArgs). A position whose sender is in pluginOwned is
// signed by a plugin, not by apsigner: it gets nothing and declares nothing.
func (e *Engine) lsigArgsForGroup(ctx context.Context, txns []types.Transaction, pluginOwned map[string]string, args LsigArgs) ([]map[string][]byte, error) {
	senders := make([]string, len(txns))
	for i, txn := range txns {
		if _, owned := pluginOwned[txn.Sender.String()]; !owned {
			senders[i] = txn.Sender.String()
		}
	}
	return e.placeLsigArgs(ctx, senders, args)
}

// placeLsigArgs gives each position of a submission the LogicSig arguments
// its signing key declares, and refuses what cannot be signed. senders holds
// each position's sender, or "" for a position apsigner does not sign, which
// gets nothing and declares nothing. The signing key is the sender's
// effective signer (its auth address when rekeyed), resolved as signing
// resolves it (judgeLsigArgs): a native key (ed25519 or native Falcon)
// declares no arguments and is given none. A name no position declares is
// refused, unless LsigArgsForItems has already found it declared across the
// items of a set. Each position is then checked against its key's
// declarations: a required argument left out, or a value of the wrong
// declared length, is refused. Every refusal comes from the cached key list,
// so judgeLsigArgs looks again after fetching it, at most once.
func (e *Engine) placeLsigArgs(ctx context.Context, senders []string, args LsigArgs) ([]map[string][]byte, error) {
	var placed []map[string][]byte
	err := e.judgeLsigArgs(ctx, senders, nil, func(signers []string) error {
		var err error
		placed, err = placeBySchemas(e.signerCacheSigningArgsFor(signers), args)
		return err
	})
	if err != nil {
		return nil, err
	}
	return placed, nil
}

// judgeLsigArgs is where placement and its up-front check fetch. It resolves
// each sender's signing key as signing does (refreshSubmitSigningState, with
// setAside as given there), then runs judge on the positions' effective
// signers: "" for a position apsigner does not sign or a sender set aside.
// judge reads the cached key list, which may be stale, so when it refuses and
// the list was not fetched for this submission already, the list is fetched
// once and judge runs again; its second answer stands.
func (e *Engine) judgeLsigArgs(ctx context.Context, senders []string, setAside map[string]error, judge func(signers []string) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	keysFresh, err := e.refreshSubmitSigningState(ctx, senders, setAside)
	if err != nil {
		return err
	}
	resolved := make([]string, len(senders))
	for i, sender := range senders {
		if _, failed := setAside[sender]; !failed {
			resolved[i] = sender
		}
	}
	err = judge(e.positionSigners(resolved))
	if err == nil || keysFresh {
		return err
	}
	if _, fetchErr := e.RefreshKeys(ctx); fetchErr != nil {
		return fmt.Errorf("%w (in the cached key list; fetching the signer's key list to look again failed: %v)", err, fetchErr)
	}
	return judge(e.positionSigners(resolved))
}

// placeBySchemas places args by the schemas each position's key declares,
// and refuses a name no schema declares (unless args were checked for the
// items of a set), a required argument left out, and a value of the wrong
// declared length.
func placeBySchemas(schemas [][]cache.SigningArgInfo, args LsigArgs) ([]map[string][]byte, error) {
	if !args.forItems {
		if undeclared := undeclaredLsigArgs(schemas, args.values); undeclared != nil {
			return nil, undeclared
		}
	}
	placed := make([]map[string][]byte, len(schemas))
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
