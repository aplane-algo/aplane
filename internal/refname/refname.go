// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package refname validates user-defined symbolic names used by apshell.
package refname

import (
	"fmt"
	"strings"
)

var reservedAliasNames = map[string]bool{
	"list":   true,
	"delete": true,
	"remove": true,
}

var dynamicSetNames = map[string]bool{
	"all":     true,
	"signers": true,
}

var reservedSetNames = map[string]bool{
	"list":   true,
	"add":    true,
	"remove": true,
	"delete": true,
}

func init() {
	for name := range dynamicSetNames {
		reservedSetNames[name] = true
	}
}

// ValidateAlias validates a persisted alias name.
func ValidateAlias(name string) error {
	return validate("alias", NormalizeAlias(name), reservedAliasNames)
}

// ValidateSet validates a persisted set name.
func ValidateSet(name string) error {
	return validate("set", NormalizeSet(name), reservedSetNames)
}

// IsDynamicSetName reports whether name is reserved for runtime-resolved sets
// such as @all and @signers.
func IsDynamicSetName(name string) bool {
	name = strings.TrimPrefix(NormalizeSet(name), "@")
	return dynamicSetNames[name]
}

// NormalizeAlias returns the canonical persisted form of an alias name.
func NormalizeAlias(name string) string {
	return strings.ToLower(name)
}

// NormalizeSet returns the canonical persisted form of a set name.
func NormalizeSet(name string) string {
	return strings.ToLower(name)
}

func validate(kind, name string, reserved map[string]bool) error {
	if name == "" {
		return fmt.Errorf("%s name cannot be empty", kind)
	}
	if reserved[name] {
		return fmt.Errorf("%s name %q is reserved", kind, name)
	}
	for _, r := range name {
		if isAllowedNameRune(r) {
			continue
		}
		return fmt.Errorf("invalid %s name %q: use only ASCII letters, numbers, '-' and '_'", kind, name)
	}
	return nil
}

func isAllowedNameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '-' || r == '_':
		return true
	default:
		return false
	}
}
