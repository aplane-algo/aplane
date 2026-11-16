// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// LookalikeField is the field name of the finding that two accounts in one
// request look alike.
const LookalikeField = "Lookalike accounts"

// lookalikeSharedCharacters is how many characters, counted from both ends
// together, two different addresses must share to be called lookalikes. An
// address shown shortened keeps a few characters of each end, and address
// poisoning searches for an address that matches them. Two unrelated
// addresses share this many by chance about once in 44 million pairs: an
// address's last character is one of only 8, its others one of 32.
const lookalikeSharedCharacters = 6

// sharedEnds counts the characters two addresses of equal length share at the
// start and at the end.
func sharedEnds(a, b string) (prefix, suffix int) {
	if len(a) != len(b) {
		return 0, 0
	}
	for prefix < len(a) && a[prefix] == b[prefix] {
		prefix++
	}
	for suffix < len(a)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	return prefix, suffix
}

// lookalikePair is two different addresses that look alike, and how many
// characters they share at each end.
type lookalikePair struct {
	a, b           string
	prefix, suffix int
}

// lookalikePairs finds the lookalikes among every address the transactions
// name: each one's sender and every field that names an account, an app
// call's referenced accounts included.
func lookalikePairs(transactions []Details) []lookalikePair {
	zero := types.Address{}.String()
	seen := map[string]bool{}
	var addresses []string
	add := func(address string) {
		if address == "" || address == zero || seen[address] {
			return
		}
		seen[address] = true
		addresses = append(addresses, address)
	}
	for _, details := range transactions {
		add(details.Sender)
		for _, f := range details.Fields {
			add(f.Party)
		}
	}
	sort.Strings(addresses)

	var pairs []lookalikePair
	for i, a := range addresses {
		for _, b := range addresses[i+1:] {
			if prefix, suffix := sharedEnds(a, b); prefix+suffix >= lookalikeSharedCharacters {
				pairs = append(pairs, lookalikePair{a: a, b: b, prefix: prefix, suffix: suffix})
			}
		}
	}
	return pairs
}

// LookalikeFindings is one finding for each pair of different addresses in
// one request that look alike. The signer's prompt and apshell's review of a
// plugin-built group both use it.
func LookalikeFindings(transactions []Details) []Finding {
	var findings []Finding
	for _, pair := range lookalikePairs(transactions) {
		a := pair.a
		var shared string
		switch {
		case pair.suffix == 0:
			shared = fmt.Sprintf("start with %s", a[:pair.prefix])
		case pair.prefix == 0:
			shared = fmt.Sprintf("end with %s", a[len(a)-pair.suffix:])
		default:
			shared = fmt.Sprintf("start with %s and end with %s", a[:pair.prefix], a[len(a)-pair.suffix:])
		}
		findings = append(findings, Finding{
			Field: LookalikeField,
			Message: fmt.Sprintf("Two different accounts in this request look alike: both %s. Compare the full addresses."+
				"\n   %s\n   %s", shared, pair.a, pair.b),
		})
	}
	return findings
}

// SetFindings sets the findings about the request as a whole, and marks the
// parties they speak of. Call it after SetParties.
func (r *Review) SetFindings() {
	transactions := make([]Details, len(r.Items))
	for i, item := range r.Items {
		transactions[i] = item.Details
	}
	r.Findings = LookalikeFindings(transactions)
	lookalike := map[string]bool{}
	for _, pair := range lookalikePairs(transactions) {
		lookalike[pair.a], lookalike[pair.b] = true, true
	}
	for i := range r.Parties {
		r.Parties[i].Lookalike = lookalike[r.Parties[i].Address]
	}
}
