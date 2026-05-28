// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypeux

import "github.com/aplane-algo/aplane/internal/keys"

const (
	AvailableToCreate    = "available to create"
	NotAvailableToCreate = "not available to create"
	TemplateProvenance   = "template provenance"
)

func AvailabilityForCreation(enabled bool) string {
	if enabled {
		return AvailableToCreate
	}
	return NotAvailableToCreate
}

func TemplateProvenanceLabel(templateProvenanceStatus string) string {
	switch templateProvenanceStatus {
	case keys.TemplateProvenanceStatusConflict, keys.TemplateProvenanceStatusUnavailable:
		return TemplateProvenance
	default:
		return ""
	}
}
