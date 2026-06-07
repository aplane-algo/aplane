// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyclass

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
)

func TestNodeRoleAllowsKeyType(t *testing.T) {
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.GuardedFalcon1024SentryEd25519V1) {
		t.Fatal("signer node rejected guarded account key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.GuardedFalcon1024SentryFalcon1024V1) {
		t.Fatal("signer node rejected Falcon-guarded account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.SentryComponentEd25519V1) {
		t.Fatal("signer node allowed Ed25519 sentry component key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.SentryComponentFalcon1024V1) {
		t.Fatal("signer node allowed Falcon sentry component key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSentry, keytypes.SentryComponentEd25519V1) {
		t.Fatal("sentry node rejected Ed25519 sentry component key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSentry, keytypes.SentryComponentFalcon1024V1) {
		t.Fatal("sentry node rejected Falcon sentry component key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSentry, "ed25519") {
		t.Fatal("sentry node allowed Ed25519 account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSentry, keytypes.GuardedFalcon1024SentryFalcon1024V1) {
		t.Fatal("sentry node allowed guarded account key")
	}
	if NodeRoleAllowsKeyType(noderole.Role("unknown"), "ed25519") {
		t.Fatal("unknown node role allowed Ed25519 account key")
	}
	if NodeRoleAllowsKeyType(noderole.Role("unknown"), keytypes.SentryComponentEd25519V1) {
		t.Fatal("unknown node role allowed sentry component key")
	}
}

func TestValidateKeyTypesAllowedForNodeRoleReportsConflicts(t *testing.T) {
	err := ValidateKeyTypesAllowedForNodeRole(noderole.RoleSentry, map[string]string{
		"ADDR": "ed25519",
		"ATT":  keytypes.SentryComponentEd25519V1,
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
