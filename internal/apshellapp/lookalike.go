// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/txnreview"
)

// ErrLookalikeDeclined is a send or sweep the user chose not to make when
// asked about a lookalike recipient. Nothing was signed.
var ErrLookalikeDeclined = errors.New("send declined")

// RecipientLookalike is a recipient typed as an address apshell does not
// know that looks like one it does: an account the signer holds an aplane
// key for, or one in the address book. Address poisoning plants such an
// address where it will be copied, matching the ends a shortened address
// shows.
type RecipientLookalike struct {
	// Typed is the address as the command named it.
	Typed string
	// Known is the known address it looks like, and Alias that address's
	// address-book name, if it has one.
	Known, Alias string
}

// Message says which addresses look alike, each in full.
func (l RecipientLookalike) Message() string {
	known := l.Known
	if l.Alias != "" {
		known = l.Alias + " (" + l.Known + ")"
	}
	return fmt.Sprintf("recipient %s is not an account apshell knows, but looks like %s. Compare the full addresses; to send to a known account, use its alias.", l.Typed, known)
}

// Warning is the lookalike as a command result's warning.
func (l RecipientLookalike) Warning() Warning {
	return Warning{Code: "recipient_lookalike", Message: l.Message()}
}

// recipientLookalikes finds the recipients typed as addresses that look like
// known ones. An alias or a set names its accounts exactly, and an address
// that is itself known is the account meant, so neither is checked.
func (a *App) recipientLookalikes(inputs []string) []RecipientLookalike {
	knownSet := map[string]bool{}
	for _, address := range a.eng.AliasCache.Aliases {
		knownSet[address] = true
	}
	for _, address := range a.eng.SignerCacheAddresses() {
		knownSet[address] = true
	}
	known := make([]string, 0, len(knownSet))
	for address := range knownSet {
		known = append(known, address)
	}
	sort.Strings(known)

	var found []RecipientLookalike
	checked := map[string]bool{}
	for _, input := range inputs {
		if input == "" || input[0] == '@' {
			continue
		}
		// An address resolves as itself before any alias, as ResolveAddress
		// resolves it.
		decoded, err := types.DecodeAddress(strings.ToUpper(input))
		if err != nil {
			continue
		}
		typed := decoded.String()
		if knownSet[typed] || checked[typed] {
			continue
		}
		checked[typed] = true
		for _, address := range known {
			if txnreview.LookAlike(typed, address) {
				found = append(found, RecipientLookalike{Typed: typed, Known: address, Alias: a.eng.GetAliasForAddress(address)})
			}
		}
	}
	return found
}
