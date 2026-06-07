// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package keyclass classifies key types for node-role inventory gates.
package keyclass

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/noderole"
)

var ErrNodeRoleConflict = errors.New("node role inventory conflict")

// NodeRoleAllowsKeyType reports whether the single-purpose node role permits
// keyType to exist in the identity's key inventory.
func NodeRoleAllowsKeyType(role noderole.Role, keyType string) bool {
	isAttestorComponent := keytypes.IsAttestorComponentKeyType(keyType)
	switch role {
	case noderole.RoleAttestor:
		return isAttestorComponent
	default:
		return !isAttestorComponent
	}
}

// ValidateKeyTypeAllowedForNodeRole returns an error if the node role forbids keyType.
func ValidateKeyTypeAllowedForNodeRole(role noderole.Role, keyType string) error {
	if NodeRoleAllowsKeyType(role, keyType) {
		return nil
	}
	return fmt.Errorf("%w: node role %q does not allow key type %q", ErrNodeRoleConflict, role, keyType)
}

// ValidateKeyTypesAllowedForNodeRole returns an error if any scanned key type is
// forbidden by the node role. The input map is address/selector -> key type.
func ValidateKeyTypesAllowedForNodeRole(role noderole.Role, scannedKeyTypes map[string]string) error {
	var conflicts []string
	for address, keyType := range scannedKeyTypes {
		if !NodeRoleAllowsKeyType(role, keyType) {
			conflicts = append(conflicts, fmt.Sprintf("%s:%s", address, keyType))
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	sort.Strings(conflicts)
	return fmt.Errorf("%w: node role %q does not allow scanned key(s): %s", ErrNodeRoleConflict, role, strings.Join(conflicts, ", "))
}
