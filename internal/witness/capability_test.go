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
		{CustodianNetworkedSigner, DomainCosignerComponent, true},
		{CustodianNetworkedSigner, MessageDomain("unknown"), false},
		{Custodian("unknown"), DomainCosignerComponent, false},
		// The retired offline custodian is now just unknown.
		{Custodian("offline_ceremony"), DomainCosignerComponent, false},
	}
	for _, test := range tests {
		if got := Allows(test.custodian, test.domain); got != test.want {
			t.Fatalf("Allows(%q, %q) = %v, want %v", test.custodian, test.domain, got, test.want)
		}
	}
}
