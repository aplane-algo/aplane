// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// Package multitemplate provides a declarative YAML-based LogicSig template system.
// Templates are embedded at compile time and automatically registered with the
// genericlsig registry.
//
// To add a new template:
// 1. Create a YAML file in lsig/multitemplate/templates/
// 2. Rebuild the binary
//
// The YAML schema supports:
// - family: Template family name (e.g., "timelock")
// - version: Version number (e.g., 2)
// - display_name: Human-readable name
// - description: Short description for UI
// - display_color: ANSI color code (optional)
// - parameters: List of parameter definitions
// - teal: TEAL source with @variable substitution
package multitemplate

import (
	"context"
	"embed"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"gopkg.in/yaml.v3"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

//go:embed templates/*
var templatesFS embed.FS

// CurrentSchemaVersion is the current YAML schema version.
// Increment when making breaking changes to the schema.
const CurrentSchemaVersion = 1

// TemplateSpec represents the YAML schema for a template definition.
// It embeds the common BaseTemplateSpec for shared metadata fields.
type TemplateSpec struct {
	templatestore.BaseTemplateSpec `yaml:",inline"`
	Parameters                     []ParameterSpec  `yaml:"parameters"`
	RuntimeArgs                    []RuntimeArgSpec `yaml:"runtime_args"` // Arguments required at signing time
	TEAL                           string           `yaml:"teal"`
}

// ParameterSpec represents a parameter definition in the YAML schema.
type ParameterSpec struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"` // address | uint64 | bytes
	Required    bool   `yaml:"required"`
	MaxLength   int    `yaml:"max_length"` // Optional: for UI input sizing

	// UI hints
	Example     string `yaml:"example"`     // Example value shown in UI
	Placeholder string `yaml:"placeholder"` // Placeholder text for input

	// Constraints (for uint64)
	Min *uint64 `yaml:"min"` // Minimum allowed value
	Max *uint64 `yaml:"max"` // Maximum allowed value

	// Default value (for optional parameters)
	Default string `yaml:"default"`
}

// RuntimeArgSpec represents a runtime argument definition in the YAML schema.
// Runtime arguments are provided at transaction signing time, not key creation time.
type RuntimeArgSpec struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"`        // bytes | string | uint64
	ByteLength  int    `yaml:"byte_length"` // Expected byte length (0 = variable)
}

// YAMLTemplate implements genericlsig.Template from a parsed YAML spec.
type YAMLTemplate struct {
	spec    *TemplateSpec
	keyType string // Computed: family-vN
}

// Compile-time check that YAMLTemplate implements Template
var _ genericlsig.Template = (*YAMLTemplate)(nil)

// NewYAMLTemplate creates a new YAMLTemplate from a spec.
func NewYAMLTemplate(spec *TemplateSpec) *YAMLTemplate {
	return &YAMLTemplate{
		spec:    spec,
		keyType: spec.KeyType(),
	}
}

// Identity methods
func (t *YAMLTemplate) KeyType() string { return t.keyType }
func (t *YAMLTemplate) Family() string  { return t.spec.Family }
func (t *YAMLTemplate) Version() int    { return t.spec.Version }

// Display methods
func (t *YAMLTemplate) DisplayName() string { return t.spec.DisplayName }
func (t *YAMLTemplate) Description() string { return t.spec.Description }
func (t *YAMLTemplate) DisplayColor() string {
	if t.spec.DisplayColor == "" {
		return "35" // Default: magenta
	}
	return t.spec.DisplayColor
}

// Category returns the LSig category (generic_lsig for templates).
func (t *YAMLTemplate) Category() string { return lsigprovider.CategoryGenericLsig }

// RuntimeArgs returns runtime arguments needed at signing time.
func (t *YAMLTemplate) RuntimeArgs() []lsigprovider.RuntimeArgDef {
	return RuntimeArgSpecToRuntimeArgDefs(t.spec.RuntimeArgs)
}

// BuildArgs assembles the LogicSig Args array.
// For generic templates, args are ordered according to RuntimeArgs().
func (t *YAMLTemplate) BuildArgs(signature []byte, runtimeArgs map[string][]byte) ([][]byte, error) {
	// Generic templates ignore signature (they don't use crypto signatures)
	var args [][]byte
	for _, argDef := range t.RuntimeArgs() {
		if val, ok := runtimeArgs[argDef.Name]; ok {
			args = append(args, val)
		} else if argDef.Required {
			return nil, fmt.Errorf("missing required arg: %s", argDef.Name)
		}
	}
	return args, nil
}

// CreationParams returns the parameter definitions for the template.
func (t *YAMLTemplate) CreationParams() []lsigprovider.ParameterDef {
	return ParameterSpecToParameterDefs(t.spec.Parameters)
}

// ParameterSpecToParameterDefs converts parameter specs to provider parameter definitions.
func ParameterSpecToParameterDefs(specs []ParameterSpec) []lsigprovider.ParameterDef {
	defs := make([]lsigprovider.ParameterDef, len(specs))
	for i, p := range specs {
		maxLen := p.MaxLength
		if maxLen == 0 {
			switch p.Type {
			case "address":
				maxLen = 58
			case "uint64":
				maxLen = 20
			case "bytes":
				maxLen = 64 // 32 bytes default
			}
		}
		defs[i] = lsigprovider.ParameterDef{
			Name:        p.Name,
			Label:       p.Label,
			Description: p.Description,
			Type:        p.Type,
			Required:    p.Required,
			MaxLength:   maxLen,
			Example:     p.Example,
			Placeholder: p.Placeholder,
			Min:         p.Min,
			Max:         p.Max,
			Default:     p.Default,
		}
	}
	return defs
}

// RuntimeArgSpecToRuntimeArgDefs converts runtime arg specs to provider runtime arg definitions.
func RuntimeArgSpecToRuntimeArgDefs(specs []RuntimeArgSpec) []lsigprovider.RuntimeArgDef {
	if len(specs) == 0 {
		return nil
	}
	defs := make([]lsigprovider.RuntimeArgDef, len(specs))
	for i, a := range specs {
		defs[i] = lsigprovider.RuntimeArgDef{
			Name:        a.Name,
			Label:       a.Label,
			Description: a.Description,
			Type:        a.Type,
			ByteLength:  a.ByteLength,
		}
	}
	return defs
}

// ValidateCreationParams validates the provided parameters against the spec.
func (t *YAMLTemplate) ValidateCreationParams(params map[string]string) error {
	return ValidateParameters(params, t.spec)
}

// GenerateTEAL generates the TEAL source code with parameters substituted.
func (t *YAMLTemplate) GenerateTEAL(params map[string]string) (string, error) {
	if err := t.ValidateCreationParams(params); err != nil {
		return "", err
	}

	teal, err := SubstituteVariables(t.spec.TEAL, params, t.spec)
	if err != nil {
		return "", fmt.Errorf("failed to substitute variables: %w", err)
	}

	return strings.TrimSpace(teal), nil
}

// Compile compiles the TEAL and returns bytecode and address.
func (t *YAMLTemplate) Compile(params map[string]string, algodClient *algod.Client) ([]byte, string, error) {
	teal, err := t.GenerateTEAL(params)
	if err != nil {
		return nil, "", err
	}

	result, err := algodClient.TealCompile([]byte(teal)).Do(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("TEAL compilation failed: %w", err)
	}

	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode bytecode: %w", err)
	}

	return bytecode, result.Hash, nil
}

// LoadTemplatesFromFS loads all YAML templates from the embedded filesystem.
func LoadTemplatesFromFS() ([]*YAMLTemplate, error) {
	entries, err := templatesFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var templates []*YAMLTemplate

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

		// Validate spec
		if err := ValidateSpec(spec); err != nil {
			return nil, fmt.Errorf("invalid template %s: %w", entry.Name(), err)
		}

		templates = append(templates, NewYAMLTemplate(spec))
	}

	return templates, nil
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
	// Validate common base fields (schema version, family, version, display_name)
	if err := spec.ValidateBase(CurrentSchemaVersion); err != nil {
		return err
	}

	if spec.TEAL == "" {
		return fmt.Errorf("teal is required")
	}

	// Validate parameter and runtime arg definitions
	if err := ValidateParameterSpecs(spec.Parameters); err != nil {
		return err
	}
	if err := ValidateRuntimeArgSpecs(spec.RuntimeArgs); err != nil {
		return err
	}

	// Validate TEAL references parameters
	if err := ValidateVariablesAgainstParams(spec.TEAL, spec); err != nil {
		return err
	}

	return nil
}

// validateDefaultValue validates that a default value is valid for its parameter type.
func validateDefaultValue(p ParameterSpec) error {
	// Use the same validation as runtime, but without min/max check here
	// (min/max will be checked separately for defaults)
	byteLength := 0
	if p.Type == "bytes" && p.MaxLength > 0 {
		byteLength = p.MaxLength / 2
	}

	if err := ValidateParameterValue(p.Default, p.Type, byteLength); err != nil {
		return err
	}

	// For uint64, also check min/max constraints on the default
	if p.Type == "uint64" {
		if err := validateUint64Constraints(p.Default, p.Min, p.Max); err != nil {
			return err
		}
	}

	return nil
}

var registerTemplatesOnce sync.Once

// RegisterTemplates loads all embedded templates and registers them with the genericlsig registry.
// This is idempotent and safe to call multiple times.
func RegisterTemplates() {
	registerTemplatesOnce.Do(func() {
		templates, err := LoadTemplatesFromFS()
		if err != nil {
			// Log error but don't panic - other templates may still work
			// In production, you might want to use a proper logger
			return
		}

		for _, tmpl := range templates {
			genericlsig.Register(tmpl)
		}
	})
}

// LoadTemplatesFromKeystore loads user-defined generic templates from the keystore.
// These are templates added via 'apstore add-template'.
// masterKey is required to decrypt the template files.
func LoadTemplatesFromKeystore(masterKey []byte) ([]*YAMLTemplate, error) {
	templateData, err := templatestore.LoadAllTemplates(templatestore.TemplateTypeGeneric, masterKey)
	if err != nil {
		return nil, err
	}

	var templates []*YAMLTemplate
	for keyType, data := range templateData {
		spec, err := ParseTemplateSpec(data)
		if err != nil {
			fmt.Printf("Warning: Failed to parse generic template %s: %v\n", keyType, err)
			continue
		}

		if err := ValidateSpec(spec); err != nil {
			fmt.Printf("Warning: Invalid generic template %s: %v\n", keyType, err)
			continue
		}

		templates = append(templates, NewYAMLTemplate(spec))
	}

	return templates, nil
}

// RegisterKeystoreTemplates loads and registers generic templates from the keystore.
// This should be called after the keystore is unlocked.
func RegisterKeystoreTemplates(masterKey []byte) error {
	templates, err := LoadTemplatesFromKeystore(masterKey)
	if err != nil {
		return fmt.Errorf("failed to load keystore templates: %w", err)
	}

	for _, tmpl := range templates {
		genericlsig.Register(tmpl)
	}

	return nil
}
