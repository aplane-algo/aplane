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
// addresses share this many by chance about once in a billion pairs.
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

// lookalikes is one finding for each pair of different addresses in the
// review that look alike. It reads every address the review names: each
// transaction's sender and every field that names an account.
func (r Review) lookalikes() []Finding {
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
	for _, item := range r.Items {
		add(item.Details.Sender)
		for _, f := range item.Details.Fields {
			add(f.Party)
		}
	}
	sort.Strings(addresses)

	var findings []Finding
	for i, a := range addresses {
		for _, b := range addresses[i+1:] {
			prefix, suffix := sharedEnds(a, b)
			if prefix+suffix < lookalikeSharedCharacters {
				continue
			}
			var shared string
			switch {
			case suffix == 0:
				shared = fmt.Sprintf("start with %s", a[:prefix])
			case prefix == 0:
				shared = fmt.Sprintf("end with %s", a[len(a)-suffix:])
			default:
				shared = fmt.Sprintf("start with %s and end with %s", a[:prefix], a[len(a)-suffix:])
			}
			findings = append(findings, Finding{
				Field: LookalikeField,
				Message: fmt.Sprintf("Two different accounts in this request look alike: both %s. Compare the full addresses."+
					"\n   %s\n   %s", shared, a, b),
			})
		}
	}
	return findings
}

// SetFindings sets the findings about the request as a whole.
func (r *Review) SetFindings() {
	r.Findings = r.lookalikes()
}
