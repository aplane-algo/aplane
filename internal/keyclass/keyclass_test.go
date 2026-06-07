// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyclass

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/noderole"
)

func TestNodeRoleAllowsKeyType(t *testing.T) {
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.AttestedFalcon1024V1) {
		t.Fatal("signer node rejected attested account key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.AttestedFalcon1024AttFalcon1024V1) {
		t.Fatal("signer node rejected Falcon-attested account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.AttestorComponentEd25519V1) {
		t.Fatal("signer node allowed Ed25519 attestor component key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.AttestorComponentFalcon1024V1) {
		t.Fatal("signer node allowed Falcon attestor component key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleAttestor, keytypes.AttestorComponentEd25519V1) {
		t.Fatal("attestor node rejected Ed25519 attestor component key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleAttestor, keytypes.AttestorComponentFalcon1024V1) {
		t.Fatal("attestor node rejected Falcon attestor component key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleAttestor, "ed25519") {
		t.Fatal("attestor node allowed Ed25519 account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleAttestor, keytypes.AttestedFalcon1024AttFalcon1024V1) {
		t.Fatal("attestor node allowed attested account key")
	}
}

func TestValidateKeyTypesAllowedForNodeRoleReportsConflicts(t *testing.T) {
	err := ValidateKeyTypesAllowedForNodeRole(noderole.RoleAttestor, map[string]string{
		"ADDR": "ed25519",
		"ATT":  keytypes.AttestorComponentEd25519V1,
	})
	if err == nil {
		t.Fatal("ValidateKeyTypesAllowedForNodeRole() error = nil")
	}
	if !strings.Contains(err.Error(), `node role "attestor"`) || !strings.Contains(err.Error(), "ADDR:ed25519") {
		t.Fatalf("error = %v, want attestor role conflict for ADDR", err)
	}
}
