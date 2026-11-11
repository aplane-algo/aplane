// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// LsigArgsByDeclaredName shares out one set of LogicSig arguments, given once
// for several transactions (a plugin group, or a send, sweep or validate over
// a set of accounts), by name: each transaction gets the arguments its
// signing key declares and no others, so a sibling position never receives
// arguments meant for another, and a native key, which declares none, gets
// none. senders holds each transaction's sender in order; an empty sender is
// a position this signer does not sign, which gets none either.
//
// A name that no position's key declares is refused: it would otherwise be
// dropped without a word.
//
// The signing key is the sender's effective signer, so the auth addresses and
// signer keys the client lacks are fetched first, as signing fetches them.
func (e *Engine) LsigArgsByDeclaredName(ctx context.Context, senders []string, args map[string][]byte) ([]map[string][]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	signed := make([]string, 0, len(senders))
	for _, sender := range senders {
		if sender != "" {
			signed = append(signed, sender)
		}
	}
	if err := e.refreshSigningStateForSenders(ctx, signed); err != nil {
		return nil, err
	}

	perPosition := make([]map[string][]byte, len(senders))
	declared := make(map[string]bool, len(args))
	for i, sender := range senders {
		if sender == "" {
			continue
		}
		for _, name := range e.signerCacheSigningArgNames(e.AuthCache.ResolveEffectiveSigner(sender)) {
			value, given := args[name]
			if !given {
				continue
			}
			if perPosition[i] == nil {
				perPosition[i] = make(map[string][]byte)
			}
			perPosition[i][name] = value
			declared[name] = true
		}
	}

	var undeclared []string
	for name := range args {
		if !declared[name] {
			undeclared = append(undeclared, "arg:"+name)
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		return nil, fmt.Errorf("%s: no transaction here is signed by a key that declares this LogicSig argument, so it would not be sent; check the name, or run keys refresh if the key is new",
			strings.Join(undeclared, ", "))
	}
	return perPosition, nil
}
