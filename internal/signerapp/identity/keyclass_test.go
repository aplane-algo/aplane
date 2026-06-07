// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/noderole"
)

func TestStoredConfigApplyRejectsMode(t *testing.T) {
	effective, err := (&StoredConfig{}).Apply(ConfigDefaults{})
	if err != nil {
		t.Fatalf("Apply(default) error = %v", err)
	}
	if effective.UserAutoApprove || effective.LockOnDisconnect || effective.SessionTimeout != 0 || effective.ApprovalWait != 0 {
		t.Fatalf("default effective config = %#v, want zero-valued overlays", effective)
	}

	if _, err := (&StoredConfig{Mode: "attestation"}).Apply(ConfigDefaults{}); err == nil {
		t.Fatal("Apply(mode) error = nil")
	} else if !strings.Contains(err.Error(), "identity config mode is unsupported") {
		t.Fatalf("Apply(mode) error = %q, want unsupported mode", err.Error())
	}
}

func TestNodeRoleAllowsKeyType(t *testing.T) {
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.AttestedFalcon1024V1) {
		t.Fatal("signer node rejected attested account key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.AttestedFalcon1024AttFalcon1024V1) {
		t.Fatal("signer node rejected Falcon-attestor attested account key")
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
		t.Fatal("attestor node allowed signing key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleAttestor, keytypes.AttestedFalcon1024AttFalcon1024V1) {
		t.Fatal("attestor node allowed attested account key")
	}
}

func TestValidateKeyTypesAllowedForNodeRoleReportsConflicts(t *testing.T) {
	err := ValidateKeyTypesAllowedForNodeRole(noderole.RoleAttestor, map[string]string{
		"ADDR": "ed25519",
	})
	if err == nil {
		t.Fatal("ValidateKeyTypesAllowedForNodeRole() error = nil")
	}
	if !strings.Contains(err.Error(), `node role "attestor"`) || !strings.Contains(err.Error(), "ADDR:ed25519") {
		t.Fatalf("error = %q, want node role and conflicting key", err.Error())
	}
}
