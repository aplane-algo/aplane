// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sourcecontext

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
)

func TestNormalizeProjectionCanonicalizesAndSortsMappings(t *testing.T) {
	autoApprove := false
	firstHash := strings.Repeat("11", 32)
	secondHash := strings.Repeat("22", 32)
	projection, err := NormalizeProjection(
		noderole.RoleSigner,
		&autoApprove,
		map[string]string{
			secondHash: "z-network",
			firstHash:  "a-network",
		},
	)
	if err != nil {
		t.Fatalf("NormalizeProjection() error = %v", err)
	}
	if projection.UserAutoApprove == nil || *projection.UserAutoApprove {
		t.Fatalf("UserAutoApprove = %v, want false", projection.UserAutoApprove)
	}
	if len(projection.GenesisHashMappings) != 2 ||
		projection.GenesisHashMappings[0].Network != "a-network" ||
		projection.GenesisHashMappings[1].Network != "z-network" {
		t.Fatalf("GenesisHashMappings = %+v, want canonical network order", projection.GenesisHashMappings)
	}
	for _, mapping := range projection.GenesisHashMappings {
		if _, err := hex.DecodeString(mapping.GenesisHash); err == nil {
			t.Fatalf("GenesisHash %q remained hex, want canonical base64", mapping.GenesisHash)
		}
	}
}

func TestNormalizeProjectionRejectsCanonicalDuplicates(t *testing.T) {
	autoApprove := false
	rawHex := strings.Repeat("33", 32)
	canonicalProjection, err := NormalizeProjection(
		noderole.RoleSigner,
		&autoApprove,
		map[string]string{rawHex: "one-network"},
	)
	if err != nil {
		t.Fatal(err)
	}
	canonical := canonicalProjection.GenesisHashMappings[0].GenesisHash
	_, err = NormalizeProjection(
		noderole.RoleSigner,
		&autoApprove,
		map[string]string{
			rawHex:    "one-network",
			canonical: "two-network",
		},
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate canonical") {
		t.Fatalf("NormalizeProjection() error = %v, want canonical duplicate rejection", err)
	}
}

func TestValidateProjectionEnforcesRoleApplicability(t *testing.T) {
	autoApprove := true
	if err := ValidateProjection(noderole.RoleSigner, Projection{}); err == nil {
		t.Fatal("ValidateProjection(signer without approval default) error = nil")
	}
	if err := ValidateProjection(noderole.RoleSentry, Projection{UserAutoApprove: &autoApprove}); err == nil {
		t.Fatal("ValidateProjection(sentry with approval default) error = nil")
	}
	if err := ValidateProjection(noderole.RoleSentry, Projection{}); err != nil {
		t.Fatalf("ValidateProjection(sentry) error = %v", err)
	}
}
