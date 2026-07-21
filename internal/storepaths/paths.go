// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package storepaths owns keystore-relative path construction for one resolved
// signer data directory.
package storepaths

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type Paths struct {
	root string
}

var keyTypeComponentShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

func NewPaths(root string) Paths {
	return Paths{root: root}
}

func (p Paths) Root() string {
	return p.root
}

func (p Paths) TemplateLibraryDir() string {
	return filepath.Join(p.root, "library", "templates")
}

func (p Paths) NodeRolePath() string {
	return filepath.Join(p.root, "node.yaml")
}

func (p Paths) NodeRoleIntegritySidecar(identityID string) string {
	return filepath.Join(p.IdentityDir(identityID), "node.yaml.hmac")
}

func validatePathComponent(label, s string) {
	if err := validatePathComponentValue(label, s); err != nil {
		panic(err.Error())
	}
}

func validatePathComponentValue(label, s string) error {
	if s == "" || strings.ContainsAny(s, "/\\\x00") || strings.Contains(s, "..") {
		return fmt.Errorf("invalid %s: %q", label, s)
	}
	return nil
}

// ValidateKeyTypeComponent checks whether keyType is safe to use in
// identity-local key type state and template paths.
func ValidateKeyTypeComponent(keyType string) error {
	if err := validatePathComponentValue("key type", keyType); err != nil {
		return err
	}
	if !keyTypeComponentShape.MatchString(keyType) {
		return fmt.Errorf("invalid key type: %q", keyType)
	}
	return nil
}

func validateKeyTypeComponent(keyType string) {
	if err := ValidateKeyTypeComponent(keyType); err != nil {
		panic(err.Error())
	}
}

func (p Paths) IdentityDir(identityID string) string {
	validatePathComponent("identity ID", identityID)
	return filepath.Join(p.root, "identities", identityID)
}

func (p Paths) KeysDir(identityID string) string {
	return filepath.Join(p.IdentityDir(identityID), "keys")
}

func (p Paths) DeletedDir(identityID string) string {
	return filepath.Join(p.IdentityDir(identityID), "deleted")
}

func (p Paths) DeletedKeysDir(identityID string) string {
	return filepath.Join(p.DeletedDir(identityID), "keys")
}

func (p Paths) BackupsRootDir() string {
	return filepath.Join(p.root, "backups")
}

func (p Paths) IdentityBackupsDir(identityID string) string {
	return filepath.Join(p.BackupsRootDir(), p.IdentityDirName(identityID))
}

func (p Paths) IdentityDirName(identityID string) string {
	validatePathComponent("identity ID", identityID)
	return identityID
}

func (p Paths) KeyTypeRecordsDir(identityID string) string {
	return filepath.Join(p.IdentityDir(identityID), "keytypes")
}

func (p Paths) SentryRefsDir(identityID string) string {
	return filepath.Join(p.IdentityDir(identityID), "sentries")
}

func (p Paths) SentryRefPath(identityID, name string) string {
	validatePathComponent("sentry reference name", name)
	return filepath.Join(p.SentryRefsDir(identityID), name+".json")
}

func (p Paths) KeyTypeRecord(identityID, keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(p.KeyTypeRecordsDir(identityID), keyType+".json")
}

func (p Paths) KeyTypeTemplate(identityID, keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(p.KeyTypeRecordsDir(identityID), keyType+".template")
}

func (p Paths) DeletedKeyTypeTemplate(identityID, keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(p.DeletedDir(identityID), "keytypes", keyType+".template")
}

func (p Paths) KeystoreMetadataDir(identityID string) string {
	return p.IdentityDir(identityID)
}
