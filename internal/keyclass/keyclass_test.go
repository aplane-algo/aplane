// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyclass

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestNodeRoleAllowsKeyType(t *testing.T) {
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.GuardedFalcon1024Sentry1024V1) {
		t.Fatal("signer node rejected guarded account key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.GuardedFalcon1024Sentry1024V1) {
		t.Fatal("signer node rejected Falcon-guarded account key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.CorridorV1) {
		t.Fatal("signer node rejected corridor account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSigner, witness.Falcon1024V1) {
		t.Fatal("signer node allowed Falcon sentry key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSigner, witness.Falcon1024V1) {
		t.Fatal("signer node allowed Falcon sentry key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSentry, witness.Falcon1024V1) {
		t.Fatal("sentry node rejected Falcon sentry key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSentry, witness.Falcon1024V1) {
		t.Fatal("sentry node rejected Falcon sentry key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSentry, "ed25519") {
		t.Fatal("sentry node allowed Ed25519 account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSentry, keytypes.GuardedFalcon1024Sentry1024V1) {
		t.Fatal("sentry node allowed guarded account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSentry, keytypes.CorridorV1) {
		t.Fatal("sentry node allowed corridor account key")
	}
	if NodeRoleAllowsKeyType(noderole.Role("unknown"), "ed25519") {
		t.Fatal("unknown node role allowed Ed25519 account key")
	}
	if NodeRoleAllowsKeyType(noderole.Role("unknown"), witness.Falcon1024V1) {
		t.Fatal("unknown node role allowed sentry key")
	}
}

func TestValidateKeyTypesAllowedForNodeRoleReportsConflicts(t *testing.T) {
	err := ValidateKeyTypesAllowedForNodeRole(noderole.RoleSentry, map[string]string{
		"ADDR": "ed25519",
		"ATT":  witness.Falcon1024V1,
	})
	if err == nil {
		t.Fatal("ValidateKeyTypesAllowedForNodeRole() error = nil")
	}
	if !errors.Is(err, ErrNodeRoleConflict) {
		t.Fatalf("error = %v, want ErrNodeRoleConflict", err)
	}
	if !strings.Contains(err.Error(), `node role "sentry"`) || !strings.Contains(err.Error(), "ADDR:ed25519") {
		t.Fatalf("error = %v, want sentry role conflict for ADDR", err)
	}
}
