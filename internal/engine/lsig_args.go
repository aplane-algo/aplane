// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// UndeclaredLsigArgsError refuses LogicSig argument names that no position's
// signing key declares. Such an argument would be sent nowhere, so it is
// refused rather than dropped without a word. Names is sorted. Each caller
// words it in the terms its arguments were given in.
type UndeclaredLsigArgsError struct {
	Names []string
}

func (e *UndeclaredLsigArgsError) Error() string {
	quoted := make([]string, len(e.Names))
	for i, name := range e.Names {
		quoted[i] = strconv.Quote(name)
	}
	if len(quoted) == 1 {
		return fmt.Sprintf("no signing key here declares the LogicSig argument %s, so it would not be sent", quoted[0])
	}
	return fmt.Sprintf("no signing key here declares the LogicSig arguments %s, so they would not be sent", strings.Join(quoted, ", "))
}

// PositionLsigArgs is one position's share of LogicSig arguments given once
// for several transactions.
type PositionLsigArgs struct {
	// Args are the given arguments that the position's signing key declares.
	Args map[string][]byte
	// Err says why the position's signing key could not be looked up: its
	// auth address, or the signer's key list, could not be fetched. The
	// position then gets no arguments and is to fail on its own, as signing
	// it would; the other positions are not affected.
	Err error
}

// ShareLsigArgsByDeclaredName shares out one set of LogicSig arguments, given
// once for one or more transactions (a send, sweep or validate over one
// account or a set, or a plugin group), by name: each position gets the
// arguments its signing key declares and no others, so a sibling position
// never receives arguments meant for another, and a native key, which
// declares none, gets none. senders holds each position's sender in order; an
// empty sender is a position this signer does not sign, which gets none
// either. The result is indexed like senders, also when no arguments are
// given.
//
// The signing key is the sender's effective signer, so the auth addresses and
// signer keys the client lacks are fetched first, as signing fetches them. A
// position whose lookup fails carries the failure in its Err.
//
// A name that no position's key declares is refused with an
// *UndeclaredLsigArgsError. While a position's key could not be looked up,
// what it declares is not known, so nothing is refused: that position fails,
// and the others get what their keys declare.
func (e *Engine) ShareLsigArgsByDeclaredName(ctx context.Context, senders []string, args map[string][]byte) ([]PositionLsigArgs, error) {
	shares := make([]PositionLsigArgs, len(senders))
	if len(args) == 0 {
		return shares, nil
	}
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	if ctx == nil {
		ctx = context.Background()
	}
	failed := e.refreshSigningStateEach(ctx, senders)

	declared := make(map[string]bool, len(args))
	for i, sender := range senders {
		if sender == "" {
			continue
		}
		if err := failed[sender]; err != nil {
			shares[i].Err = err
			continue
		}
		for _, name := range e.signerCacheSigningArgNames(e.AuthCache.ResolveEffectiveSigner(sender)) {
			value, given := args[name]
			if !given {
				continue
			}
			if shares[i].Args == nil {
				shares[i].Args = make(map[string][]byte)
			}
			shares[i].Args[name] = value
			declared[name] = true
		}
	}
	if len(failed) > 0 {
		return shares, nil
	}

	var undeclared []string
	for name := range args {
		if !declared[name] {
			undeclared = append(undeclared, name)
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		return nil, &UndeclaredLsigArgsError{Names: undeclared}
	}
	return shares, nil
}

// LsigArgsByDeclaredName is ShareLsigArgsByDeclaredName for transactions
// signed together as one group, a plugin's: a position whose signing key
// cannot be looked up fails the group, as signing it would. It returns nil
// when no arguments are given.
func (e *Engine) LsigArgsByDeclaredName(ctx context.Context, senders []string, args map[string][]byte) ([]map[string][]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	shares, err := e.ShareLsigArgsByDeclaredName(ctx, senders, args)
	if err != nil {
		return nil, err
	}
	perPosition := make([]map[string][]byte, len(shares))
	for i, share := range shares {
		if share.Err != nil {
			return nil, share.Err
		}
		perPosition[i] = share.Args
	}
	return perPosition, nil
}

// refreshSigningStateEach fetches what the client lacks to know each sender's
// signing key, as signing does: the auth address of a sender it has not
// looked up, and the signer's key list when a sender's effective signer is
// another address or a key it does not know. Unlike signing a group, it keeps
// a failure to the sender it belongs to and goes on with the others. It
// returns the failures by sender.
func (e *Engine) refreshSigningStateEach(ctx context.Context, senders []string) map[string]error {
	failed := make(map[string]error)
	var needKeys []string
	seen := make(map[string]struct{}, len(senders))
	for _, sender := range senders {
		if sender == "" {
			continue
		}
		if _, ok := seen[sender]; ok {
			continue
		}
		seen[sender] = struct{}{}
		if err := e.refreshMissingAuthAddress(ctx, sender); err != nil {
			failed[sender] = err
			continue
		}
		if e.effectiveSignerNeedsKeyRefresh(sender) {
			needKeys = append(needKeys, sender)
		}
	}
	if len(needKeys) == 0 {
		return failed
	}
	if _, err := e.RefreshKeys(ctx); err != nil {
		err = fmt.Errorf("failed to refresh signer keys: %w", err)
		for _, sender := range needKeys {
			failed[sender] = err
		}
	}
	return failed
}
