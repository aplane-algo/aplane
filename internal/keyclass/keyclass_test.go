// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyclass

import (
	"errors"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/noderole"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestNodeRoleAllowsKeyType(t *testing.T) {
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.GuardedFalcon1024Cosigner1024V1) {
		t.Fatal("signer node rejected guarded account key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, keytypes.GuardedFalcon1024Cosigner1024V1) {
		t.Fatal("signer node rejected Falcon-guarded account key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, "aplane.corridor.v1") {
		t.Fatal("signer node rejected corridor account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSigner, witness.Falcon1024V1) {
		t.Fatal("signer node allowed Falcon cosigner key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleSigner, witness.Falcon1024V1) {
		t.Fatal("signer node allowed Falcon cosigner key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleCosigner, witness.Falcon1024V1) {
		t.Fatal("cosigner node rejected Falcon cosigner key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleCosigner, witness.Falcon1024V1) {
		t.Fatal("cosigner node rejected Falcon cosigner key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleCosigner, "ed25519") {
		t.Fatal("cosigner node allowed Ed25519 account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleCosigner, nativefalcon.KeyType) {
		t.Fatal("cosigner node allowed native Falcon spending key")
	}
	if !NodeRoleAllowsKeyType(noderole.RoleSigner, nativefalcon.KeyType) {
		t.Fatal("signer node rejected native Falcon spending key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleCosigner, keytypes.GuardedFalcon1024Cosigner1024V1) {
		t.Fatal("cosigner node allowed guarded account key")
	}
	if NodeRoleAllowsKeyType(noderole.RoleCosigner, "aplane.corridor.v1") {
		t.Fatal("cosigner node allowed corridor account key")
	}
	if NodeRoleAllowsKeyType(noderole.Role("unknown"), "ed25519") {
		t.Fatal("unknown node role allowed Ed25519 account key")
	}
	if NodeRoleAllowsKeyType(noderole.Role("unknown"), witness.Falcon1024V1) {
		t.Fatal("unknown node role allowed cosigner key")
	}
}

func TestValidateKeyTypesAllowedForNodeRoleReportsConflicts(t *testing.T) {
	err := ValidateKeyTypesAllowedForNodeRole(noderole.RoleCosigner, map[string]string{
		"ADDR": "ed25519",
		"ATT":  witness.Falcon1024V1,
	})
	if err == nil {
		t.Fatal("ValidateKeyTypesAllowedForNodeRole() error = nil")
	}
	if !errors.Is(err, ErrNodeRoleConflict) {
		t.Fatalf("error = %v, want ErrNodeRoleConflict", err)
	}
	if !strings.Contains(err.Error(), `node role "cosigner"`) || !strings.Contains(err.Error(), "ADDR:ed25519") {
		t.Fatalf("error = %v, want cosigner role conflict for ADDR", err)
	}
}
