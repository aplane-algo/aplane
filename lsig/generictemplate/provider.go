// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package generictemplate provides a declarative YAML-based LogicSig template system.
// Templates can be imported from an identity keystore and registered after the
// store is unlocked.
//
// To add a template for a user:
// 1. Create a YAML file in the top-level library/templates/ directory or another path.
// 2. Install it with apstore template import.
// 3. Unlock or reload apsigner so the keystore template is registered.
//
// The YAML schema supports:
// - publisher: Template namespace owner (e.g., "aplane")
// - family: Template family name (e.g., "timelock")
// - version: Version number (e.g., 2)
// - display_name: Human-readable name
// - description: Short description for UI
// - display_color: ANSI color code (optional)
// - parameters: List of parameter definitions
// - teal: TEAL source with @variable substitution
package generictemplate

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"gopkg.in/yaml.v3"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/tealtemplate"
	"github.com/aplane-algo/aplane/internal/templatepolicy"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

// CurrentSchemaVersion is the current YAML schema version.
// Increment when making breaking changes to the schema.
const CurrentSchemaVersion = 1

const (
	TemplateModeLegacy    = "legacy"
	TemplateModeStrict    = "strict"
	TemplateModeGenerated = "generated"
)

// TemplateSpec represents the YAML schema for a template definition.
// It embeds the common BaseTemplateSpec for shared metadata fields.
type TemplateSpec struct {
	templatestore.BaseTemplateSpec `yaml:",inline"`
	TemplateMode                   string                          `yaml:"template_mode"`
	Parameters                     []ParameterSpec                 `yaml:"parameters"`
	TemplateVariables              []tealtemplate.TemplateVariable `yaml:"template_variables"`
	RuntimeArgs                    []RuntimeArgSpec                `yaml:"runtime_args"` // Arguments required at signing time
	TEAL                           string                          `yaml:"teal"`
}

// ParameterSpec represents a parameter definition in the YAML schema.
type ParameterSpec struct {
	Name        string          `yaml:"name"`
	Label       string          `yaml:"label"`
	Description string          `yaml:"description"`
	Type        string          `yaml:"type"` // address | address[] | uint64 | bytes
	Required    bool            `yaml:"required"`
	MaxLength   int             `yaml:"max_length"` // Optional: for UI input sizing
	InputModes  []InputModeSpec `yaml:"input_modes"`
	MinItems    int             `yaml:"min_items"`
	MaxItems    int             `yaml:"max_items"`

	// UI hints
	Example     string `yaml:"example"`     // Example value shown in UI
	Placeholder string `yaml:"placeholder"` // Placeholder text for input

	// Constraints (for uint64)
	Min *uint64 `yaml:"min"` // Minimum allowed value
	Max *uint64 `yaml:"max"` // Maximum allowed value

	// Default value (for optional parameters)
	Default string `yaml:"default"`
}

// InputModeSpec represents an alternate UI input mode for a creation parameter.
type InputModeSpec struct {
	Name       string `yaml:"name"`
	Label      string `yaml:"label"`
	Transform  string `yaml:"transform"`
	ByteLength int    `yaml:"byte_length"`
	InputType  string `yaml:"input_type"`
}

// RuntimeArgSpec represents a runtime argument definition in the YAML schema.
// Runtime arguments are provided at transaction signing time, not key creation time.
type RuntimeArgSpec struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"`        // bytes | string | uint64
	Required    bool   `yaml:"required"`    // If true, transaction will fail without this arg
	ByteLength  int    `yaml:"byte_length"` // Expected byte length (0 = variable)
}

// YAMLTemplate implements genericlsig.Template from a parsed YAML spec.
type YAMLTemplate struct {
	spec    *TemplateSpec
	keyType string // Computed: publisher.family.vN
}

// Compile-time check that YAMLTemplate implements Template
var _ genericlsig.Template = (*YAMLTemplate)(nil)
var _ genericlsig.SaltedTemplate = (*YAMLTemplate)(nil)

// NewYAMLTemplate creates a new YAMLTemplate from a spec.
func NewYAMLTemplate(spec *TemplateSpec) *YAMLTemplate {
	return &YAMLTemplate{
		spec:    spec,
		keyType: spec.KeyType(),
	}
}

// Identity methods
func (t *YAMLTemplate) KeyType() string       { return t.keyType }
func (t *YAMLTemplate) RoutingFamily() string { return t.spec.Family }
func (t *YAMLTemplate) Version() int          { return t.spec.Version }

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
	return lsigprovider.ValidateAndOrderArgs(t.RuntimeArgs(), runtimeArgs)
}

// CompatibilityFingerprint returns a stable semantic fingerprint for the
// behavior-bearing parts of this template definition.
func (t *YAMLTemplate) CompatibilityFingerprint() string {
	return compatibilityFingerprintForSpec(t.spec)
}

// CreationParams returns the parameter definitions for the template.
func (t *YAMLTemplate) CreationParams() []lsigprovider.ParameterDef {
	return ParameterSpecToParameterDefs(t.spec.Parameters)
}

// ParameterSpecToParameterDefs converts parameter specs to provider parameter definitions.
func ParameterSpecToParameterDefs(specs []ParameterSpec) []lsigprovider.ParameterDef {
	defs := make([]lsigprovider.ParameterDef, len(specs))
	for i, p := range specs {
		maxLen := effectiveMaxLength(p)
		defs[i] = lsigprovider.ParameterDef{
			Name:        p.Name,
			Label:       p.Label,
			Description: p.Description,
			Type:        p.Type,
			Required:    p.Required,
			MaxLength:   maxLen,
			InputModes:  inputModeSpecToInputModes(p.InputModes),
			MinItems:    p.MinItems,
			MaxItems:    p.MaxItems,
			Example:     p.Example,
			Placeholder: p.Placeholder,
			Min:         p.Min,
			Max:         p.Max,
			Default:     p.Default,
		}
	}
	return defs
}

func inputModeSpecToInputModes(specs []InputModeSpec) []lsigprovider.InputMode {
	if len(specs) == 0 {
		return nil
	}
	modes := make([]lsigprovider.InputMode, len(specs))
	for i, m := range specs {
		modes[i] = lsigprovider.InputMode{
			Name:       m.Name,
			Label:      m.Label,
			Transform:  m.Transform,
			ByteLength: m.ByteLength,
			InputType:  m.InputType,
		}
	}
	return modes
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
			Required:    a.Required,
			ByteLength:  a.ByteLength,
		}
	}
	return defs
}

// ValidateCreationParams validates the provided parameters against the spec.
func (t *YAMLTemplate) ValidateCreationParams(params map[string]string) error {
	normalized, err := lsigprovider.NormalizeCreationParams(params, t.CreationParams())
	if err != nil {
		return err
	}
	return ValidateParameters(normalized, t.spec)
}

// GenerateTEAL generates the TEAL source code with parameters substituted.
func (t *YAMLTemplate) GenerateTEAL(params map[string]string) (string, error) {
	normalizedParams, err := lsigprovider.NormalizeCreationParams(params, t.CreationParams())
	if err != nil {
		return "", err
	}
	if err := ValidateParameters(normalizedParams, t.spec); err != nil {
		return "", err
	}

	switch EffectiveTemplateMode(t.spec) {
	case TemplateModeStrict:
		rendered, err := tealtemplate.RenderStrict(t.spec.TEAL, normalizedParams, t.spec.TemplateVariables)
		if err != nil {
			return "", fmt.Errorf("failed to render strict template: %w", err)
		}
		return t.applySaltAnchor(rendered.TEAL)
	case TemplateModeLegacy, TemplateModeGenerated:
	default:
		return "", fmt.Errorf("unsupported template_mode %q", t.spec.TemplateMode)
	}

	teal, err := ExpandListTemplates(t.spec.TEAL, normalizedParams, t.spec)
	if err != nil {
		return "", fmt.Errorf("failed to expand list templates: %w", err)
	}

	teal, err = SubstituteVariables(teal, normalizedParams, t.spec)
	if err != nil {
		return "", fmt.Errorf("failed to substitute variables: %w", err)
	}

	return t.applySaltAnchor(teal)
}

// Compile compiles the TEAL and returns bytecode and address.
func (t *YAMLTemplate) Compile(ctx context.Context, params map[string]string, algodClient *algod.Client) ([]byte, string, error) {
	result, err := t.CompileWithSalt(ctx, params, algodClient)
	if err != nil {
		return nil, "", err
	}
	return result.Bytecode, result.Address.String(), nil
}

// CompileWithSalt compiles the TEAL, applies the off-curve salt counter, and
// returns bytecode, address, and salt metadata.
func (t *YAMLTemplate) CompileWithSalt(ctx context.Context, params map[string]string, algodClient *algod.Client) (lsigsalt.FindResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	teal, err := t.GenerateTEAL(params)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}

	result, err := algodClient.TealCompile([]byte(teal)).Do(ctx)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("TEAL compilation failed: %w", err)
	}

	bytecode, err := base64.StdEncoding.DecodeString(result.Result)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to decode bytecode: %w", err)
	}

	style, err := t.saltStyle()
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	if style == lsigsalt.StyleNone {
		unsalted, err := lsigsalt.UseUnmodifiedOffCurve(bytecode)
		if err != nil {
			return lsigsalt.FindResult{}, fmt.Errorf("failed to validate unsalted off-curve LogicSig address: %w", err)
		}
		return unsalted, nil
	}
	locate, err := style.Locator()
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	salted, err := lsigsalt.FindOffCurve(bytecode, locate)
	if err != nil {
		return lsigsalt.FindResult{}, fmt.Errorf("failed to derive off-curve LogicSig address: %w", err)
	}
	return salted, nil
}

func (t *YAMLTemplate) saltStyle() (lsigsalt.Style, error) {
	if t.spec.DerivationVersion == nil {
		return lsigsalt.StyleNone, nil
	}
	return SaltStyleForDerivationVersion(*t.spec.DerivationVersion)
}

func (t *YAMLTemplate) applySaltAnchor(teal string) (string, error) {
	style, err := t.saltStyle()
	if err != nil {
		return "", err
	}
	switch style {
	case lsigsalt.StyleNone:
		return teal, nil
	case lsigsalt.StylePushbytes:
		return prependSaltPreamble(teal), nil
	case lsigsalt.StyleTrailingBytecblock:
		return appendSaltTrailer(teal)
	default:
		return "", fmt.Errorf("generic template derivation does not support salt style %q", style)
	}
}

// SaltStyleForDerivationVersion maps template derivation contracts to their
// concrete salt anchor. It is shared by generic and composed YAML templates;
// Go-defined providers still choose their style directly in code.
func SaltStyleForDerivationVersion(version int) (lsigsalt.Style, error) {
	switch version {
	case templatestore.DerivationVersionPushbytes:
		return lsigsalt.StylePushbytes, nil
	case templatestore.DerivationVersionTrailingBytecblock:
		return lsigsalt.StyleTrailingBytecblock, nil
	default:
		return "", fmt.Errorf("derivation_version %d is not supported", version)
	}
}

func prependSaltPreamble(teal string) string {
	lines := strings.Split(strings.TrimSpace(teal), "\n")
	insertAt := saltPreambleInsertIndex(lines)

	out := make([]string, 0, len(lines)+2)
	out = append(out, lines[:insertAt]...)
	out = append(out, "// Salt byte, patched post-compilation to avoid ed25519-curve addresses.")
	out = append(out, saltPreambleLines()...)
	out = append(out, "")
	out = append(out, lines[insertAt:]...)
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func appendSaltTrailer(teal string) (string, error) {
	trimmed := strings.TrimSpace(teal)
	if !endsWithUnconditionalExit(trimmed) {
		return "", fmt.Errorf("derivation_version %d requires template TEAL to end with return or err before the trailing salt block", templatestore.DerivationVersionTrailingBytecblock)
	}
	trailer, err := lsigsalt.StyleTrailingBytecblock.SourceTrailer()
	if err != nil {
		return "", err
	}
	out := []string{
		trimmed,
		"",
		"// Salt byte, patched post-compilation to avoid ed25519-curve addresses.",
		strings.TrimSuffix(trailer, "\n"),
	}
	return strings.TrimSpace(strings.Join(out, "\n")), nil
}

func endsWithUnconditionalExit(teal string) bool {
	lines := strings.Split(teal, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(stripTEALComment(lines[i]))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		return len(fields) == 1 && (fields[0] == "return" || fields[0] == "err")
	}
	return false
}

func saltPreambleLines() []string {
	preamble, err := lsigsalt.StylePushbytes.SourcePreamble()
	if err != nil {
		panic("generictemplate: invalid salt style: " + err.Error())
	}
	return strings.Split(strings.TrimSuffix(preamble, "\n"), "\n")
}

func saltPreambleInsertIndex(lines []string) int {
	insertAt := 0
	if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "#pragma ") {
		insertAt = 1
	}

	sawConstantBlock := false
	for insertAt < len(lines) {
		trimmed := strings.TrimSpace(lines[insertAt])
		if strings.HasPrefix(trimmed, "intcblock ") || strings.HasPrefix(trimmed, "bytecblock ") {
			sawConstantBlock = true
			insertAt++
			continue
		}
		if sawConstantBlock && trimmed == "" {
			insertAt++
			continue
		}
		break
	}
	return insertAt
}

// loadTemplatesFrom loads YAML templates from the given filesystem, skipping
// malformed or invalid entries with a warning. This is intentionally different
// from startup provider registration: user-supplied templates are treated as
// partial and recoverable configuration, so invalid entries are logged and
// skipped while the rest continue loading.
func loadTemplatesFrom(fsys fs.FS, dir string) ([]*YAMLTemplate, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var templates []*YAMLTemplate

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			log.Printf("WARNING: skipping template %s: %v", entry.Name(), err)
			continue
		}

		spec, err := ParseTemplateSpec(data)
		if err != nil {
			log.Printf("WARNING: skipping template %s: %v", entry.Name(), err)
			continue
		}

		if err := ValidateSpec(spec); err != nil {
			log.Printf("WARNING: skipping template %s: %v", entry.Name(), err)
			continue
		}

		templates = append(templates, NewYAMLTemplate(spec))
	}

	return templates, nil
}

// ParseTemplateSpec parses YAML data into a TemplateSpec.
func ParseTemplateSpec(data []byte) (*TemplateSpec, error) {
	if err := ValidateNoSaltStyleField(data); err != nil {
		return nil, err
	}
	var spec TemplateSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}
	return &spec, nil
}

// ValidateNoSaltStyleField rejects user-authored salt-style selection. Salt
// style is an implementation detail owned by each provider family; generic and
// composed YAML templates must remain relocatable.
func ValidateNoSaltStyleField(data []byte) error {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("YAML parse error: %w", err)
	}
	if _, ok := raw["salt_style"]; ok {
		return fmt.Errorf("salt_style is not supported in YAML templates; salt style is owned by APlane")
	}
	return nil
}

// ValidateSpec validates a template spec for required fields and consistency.
func ValidateSpec(spec *TemplateSpec) error {
	// Validate common base fields (schema version, family, version, display_name)
	if err := spec.ValidateBase(CurrentSchemaVersion); err != nil {
		return err
	}
	if err := templatestore.ValidateBaseKeyType(templatestore.TemplateType(spec.TemplateType), spec.BaseKeyType); err != nil {
		return err
	}

	if spec.TEAL == "" {
		return fmt.Errorf("teal is required")
	}
	if err := ValidateRelocatableTEAL(spec.TEAL); err != nil {
		return err
	}

	// Validate parameter and runtime arg definitions
	if err := ValidateParameterSpecs(spec.Parameters); err != nil {
		return err
	}
	if err := ValidateRuntimeArgSpecs(spec.RuntimeArgs); err != nil {
		return err
	}

	if err := ValidateTemplateSpecMode(spec); err != nil {
		return err
	}
	if spec.DerivationVersion != nil &&
		*spec.DerivationVersion == templatestore.DerivationVersionTrailingBytecblock &&
		!endsWithUnconditionalExit(spec.TEAL) {
		return fmt.Errorf("derivation_version %d requires template TEAL to end with return or err before the trailing salt block", templatestore.DerivationVersionTrailingBytecblock)
	}

	return nil
}

// ValidateRelocatableTEAL rejects user-authored constant-block layout. APlane
// injects compiler-owned scaffolding before template TEAL, so templates must
// use symbolic variables instead of absolute constant indexes.
func ValidateRelocatableTEAL(teal string) error {
	for lineNo, rawLine := range strings.Split(teal, "\n") {
		line := strings.TrimSpace(stripTEALComment(rawLine))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		op := fields[0]
		switch op {
		case "bytecblock", "intcblock", "bytec", "intc":
			return fmt.Errorf("template TEAL must be relocatable: raw constant opcode %q on line %d is not allowed; use template variables instead", op, lineNo+1)
		default:
			if strings.HasPrefix(op, "bytec_") || strings.HasPrefix(op, "intc_") {
				return fmt.Errorf("template TEAL must be relocatable: raw constant opcode %q on line %d is not allowed; use template variables instead", op, lineNo+1)
			}
		}
	}
	return nil
}

func stripTEALComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func ValidateTemplateSpecMode(spec *TemplateSpec) error {
	switch EffectiveTemplateMode(spec) {
	case TemplateModeLegacy:
		if schemaVersion(spec) >= 2 {
			return fmt.Errorf("schema_version %d templates must use template_mode strict or generated", schemaVersion(spec))
		}
		return ValidateVariablesAgainstParams(spec.TEAL, spec)
	case TemplateModeStrict:
		if err := validateTemplateVariablesAgainstParameters(spec.TemplateVariables, spec.Parameters); err != nil {
			return err
		}
		return tealtemplate.ValidateStrictTemplate(spec.TEAL, spec.TemplateVariables)
	case TemplateModeGenerated:
		if len(spec.TemplateVariables) > 0 {
			return fmt.Errorf("generated templates must not declare template_variables")
		}
		if err := ValidateListTemplateSyntax(spec.TEAL, spec); err != nil {
			return err
		}
		return ValidateVariablesAgainstParams(spec.TEAL, spec)
	case "":
		return fmt.Errorf("template_mode is required for schema_version 1 templates")
	default:
		return fmt.Errorf("unsupported template_mode %q", spec.TemplateMode)
	}
}

// EffectiveTemplateMode resolves a spec's template mode, defaulting
// schema_version 1 templates to legacy mode.
func EffectiveTemplateMode(spec *TemplateSpec) string {
	if spec.TemplateMode != "" {
		return spec.TemplateMode
	}
	if schemaVersion(spec) <= 1 {
		return TemplateModeLegacy
	}
	return ""
}

func schemaVersion(spec *TemplateSpec) int {
	if spec.SchemaVersion == 0 {
		return 1
	}
	return spec.SchemaVersion
}

func validateTemplateVariablesAgainstParameters(variables []tealtemplate.TemplateVariable, params []ParameterSpec) error {
	paramTypes := make(map[string]string, len(params))
	for _, param := range params {
		paramTypes[param.Name] = param.Type
	}
	for _, variable := range variables {
		paramType, ok := paramTypes[variable.Parameter]
		if !ok {
			return fmt.Errorf("template variable %q references unknown parameter %q", variable.Name, variable.Parameter)
		}
		if variable.Type != paramType {
			return fmt.Errorf("template variable %q type %q does not match parameter %q type %q",
				variable.Name, variable.Type, variable.Parameter, paramType)
		}
	}
	return nil
}

// effectiveMaxLength resolves a parameter's MaxLength with the same
// per-type defaults the runtime defs use, so spec-time validation and
// runtime validation cannot disagree about a value's allowed length.
func effectiveMaxLength(p ParameterSpec) int {
	if p.MaxLength != 0 {
		return p.MaxLength
	}
	switch p.Type {
	case "address":
		return 58
	case "uint64":
		return 20
	case "bytes":
		return 64 // 32 bytes default
	}
	return 0
}

// validateDefaultValue validates that a default value is valid for its parameter type.
func validateDefaultValue(p ParameterSpec) error {
	// Derive the byte length exactly as the runtime defs do; a default that
	// passes spec validation must not fail at use time.
	byteLength := 0
	if p.Type == "bytes" {
		byteLength = effectiveMaxLength(p) / 2
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

// SemanticFingerprint returns a stable semantic fingerprint for the
// compatibility-bearing portions of a generic YAML template.
func SemanticFingerprint(data []byte) (string, error) {
	spec, err := ParseTemplateSpec(data)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	if err := ValidateSpec(spec); err != nil {
		return "", fmt.Errorf("invalid template: %w", err)
	}
	return compatibilityFingerprintForSpec(spec), nil
}

// PrepareKeystoreTemplateRegistration parses and validates one decrypted
// generic template. The caller remains responsible for state-record policy and
// registry conflict handling before invoking Register.
func PrepareKeystoreTemplateRegistration(keyType string, data []byte) (templatepolicy.PreparedTemplateRegistration, error) {
	spec, err := ParseTemplateSpec(data)
	if err != nil {
		return templatepolicy.PreparedTemplateRegistration{}, err
	}
	if err := ValidateSpec(spec); err != nil {
		return templatepolicy.PreparedTemplateRegistration{}, err
	}
	if spec.KeyType() != keyType {
		return templatepolicy.PreparedTemplateRegistration{}, fmt.Errorf("template key type %q does not match state key type %q", spec.KeyType(), keyType)
	}
	tmpl := NewYAMLTemplate(spec)
	return templatepolicy.PreparedTemplateRegistration{
		Fingerprint: compatibilityFingerprintForSpec(spec),
		Register: func() bool {
			return genericlsig.RegisterIfAbsent(tmpl)
		},
	}, nil
}

func compatibilityFingerprintForSpec(spec *TemplateSpec) string {
	type canonicalSpec struct {
		KeyType           string                             `json:"key_type"`
		Family            string                             `json:"family"`
		Version           int                                `json:"version"`
		DerivationVersion int                                `json:"derivation_version,omitempty"`
		TemplateMode      string                             `json:"template_mode,omitempty"`
		TemplateVariables []tealtemplate.TemplateVariable    `json:"template_variables,omitempty"`
		TEAL              string                             `json:"teal"`
		Parameters        []lsigprovider.CanonicalParameter  `json:"parameters,omitempty"`
		RuntimeArgs       []lsigprovider.CanonicalRuntimeArg `json:"runtime_args,omitempty"`
	}

	params := make([]lsigprovider.CanonicalParameter, len(spec.Parameters))
	for i, p := range spec.Parameters {
		params[i] = lsigprovider.CanonicalParameter{
			Name:      p.Name,
			Type:      p.Type,
			Required:  p.Required,
			MaxLength: p.MaxLength,
			MinItems:  p.MinItems,
			MaxItems:  p.MaxItems,
			Min:       p.Min,
			Max:       p.Max,
			Default:   p.Default,
		}
	}

	runtimeArgs := make([]lsigprovider.CanonicalRuntimeArg, len(spec.RuntimeArgs))
	for i, a := range spec.RuntimeArgs {
		runtimeArgs[i] = lsigprovider.CanonicalRuntimeArg{
			Name:       a.Name,
			Type:       a.Type,
			Required:   a.Required,
			ByteLength: a.ByteLength,
		}
	}

	return lsigprovider.HashCompatibilitySpec(canonicalSpec{
		KeyType:           spec.KeyType(),
		Family:            spec.Family,
		Version:           spec.Version,
		DerivationVersion: fingerprintDerivationVersion(spec),
		TemplateMode:      EffectiveTemplateMode(spec),
		TemplateVariables: spec.TemplateVariables,
		TEAL:              strings.TrimSpace(spec.TEAL),
		Parameters:        params,
		RuntimeArgs:       runtimeArgs,
	})
}

func fingerprintDerivationVersion(spec *TemplateSpec) int {
	if spec.DerivationVersion == nil {
		return 0
	}
	return *spec.DerivationVersion
}
