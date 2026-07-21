// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import "fmt"

// Custodian identifies a private-key execution boundary.
type Custodian string

// MessageDomain identifies a meaning-bearing witness-signature domain family.
type MessageDomain string

const (
	CustodianNetworkedSigner Custodian = "networked_signer"
	CustodianOfflineCeremony Custodian = "offline_ceremony"

	DomainSentryComponent MessageDomain = "APLANE_SENTRY_V1"
	DomainBoundedAdmin    MessageDomain = "APLANE_BOUNDED_ADMIN_AUTH_V1"
)

// Allows reports whether a custodian may produce signatures for a domain.
func Allows(custodian Custodian, domain MessageDomain) bool {
	switch custodian {
	case CustodianNetworkedSigner:
		return domain == DomainSentryComponent
	case CustodianOfflineCeremony:
		return domain == DomainBoundedAdmin
	default:
		return false
	}
}

// RequireCapability fails closed for an unsupported custodian/domain pair.
func RequireCapability(custodian Custodian, domain MessageDomain) error {
	if !Allows(custodian, domain) {
		return fmt.Errorf("witness custodian %q cannot sign domain %q", custodian, domain)
	}
	return nil
}
