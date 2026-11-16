// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txnreview

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// lookalikeOf is an address that shares its first prefix and last suffix
// characters with a and differs everywhere between.
func lookalikeOf(a string, prefix, suffix int) string {
	middle := []byte(a[prefix : len(a)-suffix])
	for i := range middle {
		if middle[i] == 'A' {
			middle[i] = 'B'
		} else {
			middle[i] = 'A'
		}
	}
	return a[:prefix] + string(middle) + a[len(a)-suffix:]
}

func reviewNaming(addresses ...string) Review {
	item := Item{Details: Details{Sender: addresses[0]}}
	for _, a := range addresses[1:] {
		item.Details.Fields = append(item.Details.Fields, Field{Label: "To", Value: a, Party: a})
	}
	return Review{Items: []Item{item}}
}

func TestLookalikeFinding(t *testing.T) {
	real := detailsAddr(7).String()
	tests := []struct {
		name      string
		other     string
		wantWords string // empty: no finding
	}{
		{"same four characters at each end", lookalikeOf(real, 4, 4), "both start with " + real[:4] + " and end with " + real[len(real)-4:]},
		{"three at each end", lookalikeOf(real, 3, 3), "both start with " + real[:3] + " and end with " + real[len(real)-3:]},
		{"only the start", lookalikeOf(real, 6, 0), "both start with " + real[:6]},
		{"only the end", lookalikeOf(real, 0, 6), "both end with " + real[len(real)-6:]},
		{"five shared characters", lookalikeOf(real, 3, 2), ""},
		{"an unrelated address", detailsAddr(9).String(), ""},
		{"the same address", real, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			review := reviewNaming(real, tc.other)
			review.SetFindings()
			if tc.wantWords == "" {
				if len(review.Findings) != 0 {
					t.Fatalf("findings = %+v, want none", review.Findings)
				}
				return
			}
			if len(review.Findings) != 1 {
				t.Fatalf("findings = %+v, want one", review.Findings)
			}
			f := review.Findings[0]
			if f.Field != LookalikeField || f.Critical {
				t.Errorf("finding = %+v", f)
			}
			for _, want := range []string{tc.wantWords, real, tc.other} {
				if !strings.Contains(f.Message, want) {
					t.Errorf("message lacks %q:\n%s", want, f.Message)
				}
			}
		})
	}
}

// The zero address is in many transactions and is no one's lookalike, and
// each pair is reported once however often the request names it.
func TestLookalikeFindingIgnoresTheZeroAddressAndRepeats(t *testing.T) {
	real := detailsAddr(7).String()
	fake := lookalikeOf(real, 4, 4)
	zero := types.Address{}.String()
	review := reviewNaming(real, fake, zero, fake, real)
	review.Items = append(review.Items, Item{Details: Details{Sender: fake}})
	review.SetFindings()
	if len(review.Findings) != 1 {
		t.Fatalf("findings = %+v, want one", review.Findings)
	}
	if strings.Contains(review.Findings[0].Message, zero) {
		t.Fatalf("the zero address is called a lookalike:\n%s", review.Findings[0].Message)
	}
}
