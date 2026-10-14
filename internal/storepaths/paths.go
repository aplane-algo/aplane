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
	root               string
	productDir         string
	productBackups     string
	activeGenerationID string
}

// BindActive returns a copy carrying one already-authenticated active
// generation capability. APIs that still accept Paths resolve this binding
// without consulting a public pointer. Only a canonical generation owned by
// this Paths value can be bound; staging and quarantine paths are rejected.
func (p Paths) BindActive(gen GenPaths) (Paths, error) {
	if err := ValidateGenerationID(gen.GenerationID()); err != nil {
		return Paths{}, err
	}
	want := filepath.Clean(p.GenerationDir(gen.GenerationID()))
	if filepath.Clean(gen.Dir()) != want {
		return Paths{}, fmt.Errorf("generation %s is not owned by product store %s", gen.GenerationID(), p.ProductDir())
	}
	p.activeGenerationID = gen.GenerationID()
	return p, nil
}

// BoundActiveGeneration reports the authenticated generation capability
// carried by this Paths copy, if any.
func (p Paths) BoundActiveGeneration() (string, bool) {
	return p.activeGenerationID, p.activeGenerationID != ""
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

// DefaultPolicyFileName is the node's default policy document at a
// generation root, on both node roles.
const DefaultPolicyFileName = "default.json"

var (
	witnessKeyIDPattern = regexp.MustCompile(`^[A-Z2-7]{52}$`)
	addressPattern      = regexp.MustCompile(`^[A-Z2-7]{58}$`)
)

// ValidatePolicySelector reports whether selector names a key that may have
// a policy document of its own: an Algorand address (signer node) or a
// Witness Key ID (cosigner node), by shape. The policy decoder checks the
// checksum and the role; this guards the file name.
func ValidatePolicySelector(selector string) error {
	if !addressPattern.MatchString(selector) && !witnessKeyIDPattern.MatchString(selector) {
		return fmt.Errorf("invalid policy key path component %q", selector)
	}
	return nil
}

func validatePolicySelector(selector string) {
	if err := ValidatePolicySelector(selector); err != nil {
		panic(err.Error())
	}
}

func validateKeyTypeComponent(keyType string) {
	if err := ValidateKeyTypeComponent(keyType); err != nil {
		panic(err.Error())
	}
}

func (p Paths) BackupsRootDir() string {
	return filepath.Join(p.root, "backups")
}

func (p Paths) CosignerRefsDir() string {
	return filepath.Join(p.ProductDir(), "cosigners")
}

func (p Paths) CosignerRefPath(name string) string {
	validatePathComponent("cosigner reference name", name)
	return filepath.Join(p.CosignerRefsDir(), name+".json")
}

func (p Paths) KeystoreMetadataDir() string {
	return p.ProductDir()
}
