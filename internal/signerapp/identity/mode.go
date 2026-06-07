// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package identity

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/noderole"
)

// Mode controls which key classes an identity is allowed to hold and use.
type Mode string

const (
	ModeSigning     Mode = "signing"
	ModeAttestation Mode = "attestation"
	ModeDual        Mode = "dual"
)

// NormalizeMode returns the default signing mode for the zero value.
func NormalizeMode(mode Mode) Mode {
	switch mode {
	case ModeSigning, ModeAttestation, ModeDual:
		return mode
	default:
		return ModeSigning
	}
}

// ModeForNodeRole bridges the durable single-purpose node role into the
// remaining internal mode-based key gates while those call sites are converted.
func ModeForNodeRole(role noderole.Role) Mode {
	switch role {
	case noderole.RoleAttestor:
		return ModeAttestation
	default:
		return ModeSigning
	}
}

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
	return fmt.Errorf("node role %q does not allow key type %q", role, keyType)
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
	return fmt.Errorf("node role %q does not allow scanned key(s): %s", role, strings.Join(conflicts, ", "))
}

// ParseMode validates a stored identity mode string.
func ParseMode(raw string) (Mode, error) {
	switch mode := Mode(strings.ToLower(strings.TrimSpace(raw))); mode {
	case "":
		return ModeSigning, nil
	case ModeSigning, ModeAttestation, ModeDual:
		return mode, nil
	default:
		return "", fmt.Errorf("mode %q must be one of: %s, %s, %s", raw, ModeSigning, ModeAttestation, ModeDual)
	}
}

// AllowsKeyType reports whether the identity mode permits keyType to exist in
// the identity's key inventory.
func (m Mode) AllowsKeyType(keyType string) bool {
	mode := NormalizeMode(m)
	isAttestorComponent := keytypes.IsAttestorComponentKeyType(keyType)
	switch mode {
	case ModeSigning:
		return !isAttestorComponent
	case ModeAttestation:
		return isAttestorComponent
	case ModeDual:
		return true
	default:
		return false
	}
}

// ValidateKeyTypeAllowed returns an error if mode forbids keyType.
func ValidateKeyTypeAllowed(mode Mode, keyType string) error {
	mode = NormalizeMode(mode)
	if mode.AllowsKeyType(keyType) {
		return nil
	}
	return fmt.Errorf("identity mode %q does not allow key type %q", mode, keyType)
}

// ValidateKeyTypesAllowed returns an error if any scanned key type is forbidden
// by mode. The input map is address/selector -> key type.
func ValidateKeyTypesAllowed(mode Mode, scannedKeyTypes map[string]string) error {
	mode = NormalizeMode(mode)
	var conflicts []string
	for address, keyType := range scannedKeyTypes {
		if !mode.AllowsKeyType(keyType) {
			conflicts = append(conflicts, fmt.Sprintf("%s:%s", address, keyType))
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	sort.Strings(conflicts)
	return fmt.Errorf("identity mode %q does not allow scanned key(s): %s", mode, strings.Join(conflicts, ", "))
}
