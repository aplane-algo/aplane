// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "fmt"

// refuseRepeatedSendAccounts refuses a send whose senders or recipients name
// one account more than once after sets and aliases are expanded to addresses:
// an alias and its address, or a set and one of its members listed again. A
// send builds one transaction per listed account, so a repeat pays that
// recipient, or charges that sender, twice. The repeat is refused rather than
// dropped, so a mistake in the set is not hidden.
func (a *App) refuseRepeatedSendAccounts(fromAddresses, toAddresses []string) error {
	sides := []struct {
		role      string
		addresses []string
	}{
		{"sender", fromAddresses},
		{"recipient", toAddresses},
	}
	for _, side := range sides {
		seen := make(map[string]bool, len(side.addresses))
		for _, address := range side.addresses {
			if seen[address] {
				return fmt.Errorf("%s %s is listed more than once (sets and aliases are expanded to addresses); list each account once",
					side.role, a.accountLabel(address))
			}
			seen[address] = true
		}
	}
	return nil
}
