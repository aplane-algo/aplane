// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package template provides a declarative YAML-based system for defining
// Falcon-1024 DSA compositions with parameterized TEAL suffixes.
//
// Templates can be loaded from two sources:
//  1. Embedded at compile time (optional) - place YAML files in templates/
//  2. Keystore (primary) - add via 'apstore add-falcon-template'
//
// Each template combines the Falcon-1024 DSA base with a TEAL suffix that uses
// @variable substitution for creation-time parameters, and is registered with logicsigdsa.
//
// Example YAML:
//
//	schema_version: 1
//	family: falcon1024-hashlock
//	version: 1
//	display_name: "Falcon-1024 Hashlock"
//	description: "Falcon signature with SHA256 hash verification"
//	parameters:
//	  - name: hash
//	    type: bytes
//	    required: true
//	    max_length: 64
//	    label: "SHA256 Hash"
//	runtime_args:
//	  - name: preimage
//	    type: bytes
//	    label: "Secret Preimage"
//	teal: |
//	  txn RekeyTo
//	  global ZeroAddress
//	  ==
//	  assert
//	  arg 1
//	  sha256
//	  byte @hash
//	  ==
//	  assert
package template

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/tealsubst"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/internal/util"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconkeys "github.com/aplane-algo/aplane/lsig/falcon1024/keys"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
	"github.com/aplane-algo/aplane/lsig/multitemplate"
)

//go:embed all:templates
var templatesFS embed.FS

// CurrentSchemaVersion is the current YAML schema version.
const CurrentSchemaVersion = 1

// TemplateSpec represents the YAML schema for a Falcon template definition.
// It embeds the common BaseTemplateSpec and adds parameterized TEAL fields.
type TemplateSpec struct {
	templatestore.BaseTemplateSpec `yaml:",inline"`
	Parameters                     []multitemplate.ParameterSpec  `yaml:"parameters"`
	RuntimeArgs                    []multitemplate.RuntimeArgSpec `yaml:"runtime_args"`
	TEAL                           string                         `yaml:"teal"`
}

// LoadTemplatesFromFS loads all YAML templates from the embedded filesystem.
// Returns an empty slice if no templates are embedded (this is not an error).
func LoadTemplatesFromFS() ([]*v1.ComposedDSA, error) {
	entries, err := templatesFS.ReadDir("templates")
	if err != nil {
		// Directory doesn't exist in embed - that's OK, no embedded templates
		return nil, nil
	}

	var providers []*v1.ComposedDSA

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join("templates", entry.Name())
		data, err := templatesFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read template %s: %w", entry.Name(), err)
		}

		spec, err := ParseTemplateSpec(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", entry.Name(), err)
		}

		if err := ValidateSpec(spec); err != nil {
			return nil, fmt.Errorf("invalid template %s: %w", entry.Name(), err)
		}

		provider, err := CreateProviderFromSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider from %s: %w", entry.Name(), err)
		}

		providers = append(providers, provider)
	}

	return providers, nil
}

// ParseTemplateSpec parses YAML data into a TemplateSpec.
func ParseTemplateSpec(data []byte) (*TemplateSpec, error) {
	var spec TemplateSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}
	return &spec, nil
}

// ValidateSpec validates a template spec for required fields and consistency.
func ValidateSpec(spec *TemplateSpec) error {
	// Validate common fields
	if err := spec.ValidateBase(CurrentSchemaVersion); err != nil {
		return err
	}

	// Require TEAL suffix - a template with no TEAL would be identical to
	// the base falcon1024 type and is likely accidental
	if strings.TrimSpace(spec.TEAL) == "" {
		return fmt.Errorf("teal is required (use falcon1024-v1 for unconstrained signatures)")
	}

	// Validate parameter and runtime arg definitions
	if err := multitemplate.ValidateParameterSpecs(spec.Parameters); err != nil {
		return err
	}
	if err := multitemplate.ValidateRuntimeArgSpecs(spec.RuntimeArgs); err != nil {
		return err
	}

	// Validate TEAL references parameters
	paramNames := make([]string, len(spec.Parameters))
	for i, p := range spec.Parameters {
		paramNames[i] = p.Name
	}
	if err := tealsubst.ValidateVariablesAgainstParams(spec.TEAL, paramNames); err != nil {
		return err
	}

	return nil
}

// CreateProviderFromSpec creates a ComposedDSA from a template spec.
func CreateProviderFromSpec(spec *TemplateSpec) (*v1.ComposedDSA, error) {
	return v1.NewComposedDSA(v1.ComposedDSAConfig{
		KeyType:     spec.KeyType(),
		FamilyName:  family.FalconBase.Name(),
		Version:     spec.Version,
		DisplayName: spec.DisplayName,
		Description: spec.Description,
		Base:        family.FalconBase,
		TEALSuffix:  strings.TrimSpace(spec.TEAL),
		Params:      multitemplate.ParameterSpecToParameterDefs(spec.Parameters),
		RuntimeArgs: multitemplate.RuntimeArgSpecToRuntimeArgDefs(spec.RuntimeArgs),
	}), nil
}

var registerTemplatesOnce sync.Once

// RegisterTemplates loads all embedded templates and registers them with logicsigdsa.
// Also registers key processors so keys can be imported and addresses derived.
// This is idempotent and safe to call multiple times.
// If no templates are embedded, this is a no-op (not an error).
func RegisterTemplates() {
	registerTemplatesOnce.Do(func() {
		providers, err := LoadTemplatesFromFS()
		if err != nil {
			// Log error but don't panic
			fmt.Printf("Warning: failed to load falcon1024 templates: %v\n", err)
			return
		}

		for _, provider := range providers {
			registerProvider(provider)
		}
	})
}

// registerProvider registers a single provider with all necessary registries.
func registerProvider(provider *v1.ComposedDSA) {
	keyType := provider.KeyType()

	// Register with logicsigdsa for signing/derivation
	logicsigdsa.Register(provider)

	// Register address deriver for address derivation
	util.RegisterAddressDeriver(keyType, falconkeys.GetFalconAddressDeriverForType(keyType))
}

// LoadTemplatesFromKeystore loads user-defined Falcon templates from the keystore.
// These are templates added via 'apstore add-falcon-template'.
// masterKey is required to decrypt the template files.
func LoadTemplatesFromKeystore(identityID string, masterKey []byte) ([]*v1.ComposedDSA, error) {
	templateData, err := templatestore.LoadAllTemplates(identityID, templatestore.TemplateTypeFalcon, masterKey)
	if err != nil {
		return nil, err
	}

	var providers []*v1.ComposedDSA
	for keyType, data := range templateData {
		spec, err := ParseTemplateSpec(data)
		if err != nil {
			fmt.Printf("Warning: Failed to parse falcon template %s: %v\n", keyType, err)
			continue
		}

		if err := ValidateSpec(spec); err != nil {
			fmt.Printf("Warning: Invalid falcon template %s: %v\n", keyType, err)
			continue
		}

		provider, err := CreateProviderFromSpec(spec)
		if err != nil {
			fmt.Printf("Warning: Failed to create provider from %s: %v\n", keyType, err)
			continue
		}

		providers = append(providers, provider)
	}

	return providers, nil
}

// RegisterKeystoreTemplates loads and registers templates from the keystore.
// This should be called after the keystore is unlocked.
func RegisterKeystoreTemplates(identityID string, masterKey []byte) error {
	providers, err := LoadTemplatesFromKeystore(identityID, masterKey)
	if err != nil {
		return fmt.Errorf("failed to load keystore templates: %w", err)
	}

	for _, provider := range providers {
		registerProvider(provider)
	}

	return nil
}
