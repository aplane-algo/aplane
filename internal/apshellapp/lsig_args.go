// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "context"

// lsigArgsForSenders gives each sender of a command the LogicSig arguments
// typed once for the whole command. Over one account they go as typed, and
// that key's own checks refuse a name it does not take. Over several accounts
// (a send, sweep or validate over a set) each gets the arguments its key
// declares, as a plugin group's positions do, so an account whose key takes
// none, a native key among them, is sent none, and a name no account's key
// declares is refused. The result is indexed like senders.
func (a *App) lsigArgsForSenders(ctx context.Context, senders []string, args map[string][]byte) ([]map[string][]byte, error) {
	perSender := make([]map[string][]byte, len(senders))
	if len(args) == 0 {
		return perSender, nil
	}
	distinct := make(map[string]struct{}, len(senders))
	for _, sender := range senders {
		distinct[sender] = struct{}{}
	}
	if len(distinct) <= 1 {
		for i := range perSender {
			perSender[i] = args
		}
		return perSender, nil
	}
	shared, err := a.eng.LsigArgsByDeclaredName(ctx, senders, args)
	if err != nil {
		return nil, err
	}
	copy(perSender, shared)
	return perSender, nil
}
