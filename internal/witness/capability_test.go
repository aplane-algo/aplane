// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import "testing"

func TestWitnessCustodianCapabilities(t *testing.T) {
	tests := []struct {
		custodian Custodian
		domain    MessageDomain
		want      bool
	}{
		{CustodianNetworkedSigner, DomainSentryComponent, true},
		{CustodianNetworkedSigner, DomainBoundedAdmin, false},
		{CustodianOfflineCeremony, DomainSentryComponent, false},
		{CustodianOfflineCeremony, DomainBoundedAdmin, true},
		{Custodian("unknown"), DomainSentryComponent, false},
	}
	for _, test := range tests {
		if got := Allows(test.custodian, test.domain); got != test.want {
			t.Fatalf("Allows(%q, %q) = %v, want %v", test.custodian, test.domain, got, test.want)
		}
	}
}
