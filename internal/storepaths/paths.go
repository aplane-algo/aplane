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

	"github.com/aplane-algo/aplane/internal/productmode"
)

type Paths struct {
	root           string
	productDir     string
	productBackups string
}

var (
	keyTypeComponentShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
)

func NewPaths(root string) Paths {
	return Paths{
		root:           root,
		productDir:     filepath.Join(root, "identities", productmode.IdentityID),
		productBackups: filepath.Join(root, "backups", productmode.IdentityID),
	}
}

// ProductDir is the one product signing store at identities/default.
func (p Paths) ProductDir() string {
	return p.productDir
}

// ProductBackupsDir is the one managed backup namespace at backups/default.
func (p Paths) ProductBackupsDir() string {
	return p.productBackups
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

func (p Paths) NodeRoleIntegritySidecar() string {
	return filepath.Join(p.ProductDir(), "node.yaml.hmac")
}

// RotationSnapshotPath is the target-term-sealed cutover inventory pinned by
// a pending keyring descriptor.
func (p Paths) RotationSnapshotPath() string {
	return filepath.Join(p.ProductDir(), "rotation.snapshot.enc")
}

// RotationBaselinePath is the current-term-sealed post-rewrap inventory
// baseline used by generation rollback validation.
func (p Paths) RotationBaselinePath() string {
	return filepath.Join(p.ProductDir(), "rotation.baseline.enc")
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
// product-store key type state and template paths.
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

// LegacyKeysDir returns the pre-generation key namespace. It is not an active
// store path; normal consumers must resolve storepaths.ActivePaths through
// genstore.ResolveActive. This path remains available only for recovery probes
// and tests that verify legacy state is not treated as active.
func (p Paths) LegacyKeysDir() string {
	return filepath.Join(p.ProductDir(), "keys")
}

func (p Paths) DeletedDir() string {
	return filepath.Join(p.ProductDir(), "deleted")
}

func (p Paths) DeletedKeysDir() string {
	return filepath.Join(p.DeletedDir(), "keys")
}

func (p Paths) BackupsRootDir() string {
	return filepath.Join(p.root, "backups")
}

// LegacyKeyTypeRecordsDir returns the pre-generation key-type namespace. It is
// not an active store path; see LegacyKeysDir.
func (p Paths) LegacyKeyTypeRecordsDir() string {
	return filepath.Join(p.ProductDir(), "keytypes")
}

func (p Paths) SentryRefsDir() string {
	return filepath.Join(p.ProductDir(), "sentries")
}

func (p Paths) SentryRefPath(name string) string {
	validatePathComponent("sentry reference name", name)
	return filepath.Join(p.SentryRefsDir(), name+".json")
}

func (p Paths) LegacyKeyTypeRecord(keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(p.LegacyKeyTypeRecordsDir(), keyType+".json")
}

func (p Paths) LegacyKeyTypeTemplate(keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(p.LegacyKeyTypeRecordsDir(), keyType+".template")
}

func (p Paths) DeletedKeyTypeTemplate(keyType string) string {
	validateKeyTypeComponent(keyType)
	return filepath.Join(p.DeletedDir(), "keytypes", keyType+".template")
}

func (p Paths) KeystoreMetadataDir() string {
	return p.ProductDir()
}
