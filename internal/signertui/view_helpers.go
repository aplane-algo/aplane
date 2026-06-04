// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Helper functions for key type options and input field configuration.

import (
	"fmt"
	"sync"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

var serverKeyTypes struct {
	sync.RWMutex
	items []protocol.KeyTypeInfo
}

func setServerKeyTypes(items []protocol.KeyTypeInfo) {
	serverKeyTypes.Lock()
	defer serverKeyTypes.Unlock()

	serverKeyTypes.items = append([]protocol.KeyTypeInfo(nil), items...)
}

func getServerKeyTypes() []protocol.KeyTypeInfo {
	serverKeyTypes.RLock()
	defer serverKeyTypes.RUnlock()
	return append([]protocol.KeyTypeInfo(nil), serverKeyTypes.items...)
}

func findServerKeyType(keyType string) (protocol.KeyTypeInfo, bool) {
	for _, info := range getServerKeyTypes() {
		if info.KeyType == keyType {
			return info, true
		}
	}
	return protocol.KeyTypeInfo{}, false
}

func getServerImportKeyTypes() []protocol.KeyTypeInfo {
	var out []protocol.KeyTypeInfo
	for _, info := range getServerKeyTypes() {
		if info.MnemonicImport {
			out = append(out, info)
		}
	}
	return out
}

// getKeyTypeOptions returns a list of key type display strings for UI selection.
// Uses keymgmt.GetValidKeyTypes() which returns versioned types (e.g., "aplane.falcon1024.v1").
func getKeyTypeOptions() []string {
	if types := getServerImportKeyTypes(); len(types) > 0 {
		options := make([]string, len(types))
		for i, info := range types {
			if info.MnemonicWordCount > 0 {
				options[i] = fmt.Sprintf("%s (%d words)", displayKeyType(info.KeyType), info.MnemonicWordCount)
			} else {
				options[i] = displayKeyType(info.KeyType)
			}
		}
		return options
	}

	types := keymgmt.GetMnemonicImportKeyTypesWithActivated(nil)
	options := make([]string, len(types))
	for i, keyType := range types {
		meta, err := algorithm.GetMetadata(keyType)
		if err == nil && meta != nil {
			options[i] = fmt.Sprintf("%s (%d words)", displayKeyType(keyType), meta.MnemonicWordCount())
		} else {
			options[i] = displayKeyType(keyType)
		}
	}
	return options
}

// getGenerateKeyTypeOptions returns key type options for the generate form.
// Includes both cryptographic key types (versioned) and generic LogicSig templates.
func getGenerateKeyTypeOptions() []string {
	if types := getServerKeyTypes(); len(types) > 0 {
		options := make([]string, len(types))
		for i, info := range types {
			options[i] = displayKeyType(info.KeyType)
		}
		return options
	}

	// Get cryptographic key types from keymgmt (returns versioned types)
	types := keymgmt.GetValidKeyTypes()
	options := make([]string, 0, len(types)+genericlsig.Count())

	for _, keyType := range types {
		options = append(options, displayKeyType(keyType))
	}

	// Add generic LogicSig templates from registry
	for _, template := range genericlsig.GetAll() {
		options = append(options, displayKeyType(template.KeyType()))
	}

	return options
}

func getKeyTypeSelectionLabel(keyType string) string {
	if info, ok := findServerKeyType(keyType); ok {
		if info.DisplayName != "" {
			return info.DisplayName
		}
		if info.Family != "" {
			return info.Family
		}
		return displayKeyType(info.KeyType)
	}
	if spec := getParamSpecForKeyType(keyType); spec != nil && spec.DisplayName != "" {
		return spec.DisplayName
	}
	if meta, err := algorithm.GetMetadata(keyType); err == nil && meta != nil {
		return algorithm.DisplayLabel(meta)
	}
	if template := genericlsig.Get(keyType); template != nil {
		return "generic LogicSig"
	}
	return displayKeyType(keyType)
}

type paramSpec struct {
	DisplayName string
	Description string
	Params      []lsigprovider.ParameterDef
	Validate    func(map[string]string) error
}

func getParamSpecForKeyType(keyType string) *paramSpec {
	if keyType == "" {
		return nil
	}

	if info, ok := findServerKeyType(keyType); ok && len(info.CreationParams) > 0 {
		params := protocolParamInfosToDefs(info.CreationParams)
		return &paramSpec{
			DisplayName: info.DisplayName,
			Description: info.Description,
			Params:      params,
			Validate: func(values map[string]string) error {
				normalized, err := lsigprovider.NormalizeCreationParams(values, params)
				if err != nil {
					return err
				}
				return generictemplate.ValidateParameterValues(normalized, params)
			},
		}
	}

	// Use unified lsigprovider registry
	provider := lsigprovider.Get(keyType)
	if provider == nil {
		return nil
	}

	params := provider.CreationParams()
	if len(params) == 0 {
		return nil
	}

	return &paramSpec{
		DisplayName: provider.DisplayName(),
		Description: provider.Description(),
		Params:      params,
		Validate:    provider.ValidateCreationParams,
	}
}

func getImportKeyTypeByIndex(index int) string {
	if types := getServerImportKeyTypes(); len(types) > 0 {
		if index >= 0 && index < len(types) {
			return types[index].KeyType
		}
		return ""
	}
	types := keymgmt.GetMnemonicImportKeyTypesWithActivated(nil)
	if index >= 0 && index < len(types) {
		return types[index]
	}
	return ""
}

// getKeyTypeByIndex returns the key type identifier for the given index.
// Handles both cryptographic key types (versioned) and generic LogicSig templates.
func getKeyTypeByIndex(index int) string {
	if types := getServerKeyTypes(); len(types) > 0 {
		if index >= 0 && index < len(types) {
			return types[index].KeyType
		}
		return ""
	}

	types := keymgmt.GetValidKeyTypes()
	if index >= 0 && index < len(types) {
		return types[index]
	}

	// Index beyond registered key types refers to generic lsig templates
	genericIndex := index - len(types)
	genericTemplates := genericlsig.GetAll()
	if genericIndex >= 0 && genericIndex < len(genericTemplates) {
		return genericTemplates[genericIndex].KeyType()
	}

	return ""
}

// getKeyTypeCount returns the total number of key types (cryptographic + generic lsig).
func getKeyTypeCount() int {
	if types := getServerKeyTypes(); len(types) > 0 {
		return len(types)
	}
	return len(keymgmt.GetValidKeyTypes()) + genericlsig.Count()
}

func getImportKeyTypeCount() int {
	if types := getServerImportKeyTypes(); len(types) > 0 {
		return len(types)
	}
	return len(keymgmt.GetMnemonicImportKeyTypesWithActivated(nil))
}

// getExpectedWordCount returns the expected mnemonic word count for a key type index.
func getExpectedWordCount(keyTypeIndex int) int {
	keyType := getKeyTypeByIndex(keyTypeIndex)
	return getExpectedWordCountForKeyType(keyType)
}

func getExpectedImportWordCount(keyTypeIndex int) int {
	keyType := getImportKeyTypeByIndex(keyTypeIndex)
	return getExpectedWordCountForKeyType(keyType)
}

func getExpectedWordCountForKeyType(keyType string) int {
	if keyType == "" {
		return 25 // default for ed25519
	}
	if info, ok := findServerKeyType(keyType); ok {
		if info.MnemonicWordCount > 0 {
			return info.MnemonicWordCount
		}
		return 0
	}
	if dsa := logicsigdsa.Get(keyType); dsa != nil {
		return dsa.MnemonicWordCount()
	}
	meta, err := algorithm.GetMetadata(keyType)
	if err == nil && meta != nil {
		return meta.MnemonicWordCount()
	}
	return 25 // default
}

func protocolParamInfosToDefs(params []protocol.TemplateParamInfo) []lsigprovider.ParameterDef {
	defs := make([]lsigprovider.ParameterDef, len(params))
	for i, p := range params {
		defs[i] = lsigprovider.ParameterDef{
			Name:        p.Name,
			Label:       p.Label,
			Description: p.Description,
			Type:        p.Type,
			Required:    p.Required,
			MaxLength:   p.MaxLength,
			InputModes:  protocolInputModesToDefs(p.InputModes),
			Options:     append([]string(nil), p.Options...),
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

func protocolInputModesToDefs(modes []protocol.InputModeInfo) []lsigprovider.InputMode {
	if len(modes) == 0 {
		return nil
	}
	out := make([]lsigprovider.InputMode, len(modes))
	for i, mode := range modes {
		out[i] = lsigprovider.InputMode{
			Name:       mode.Name,
			Label:      mode.Label,
			Transform:  mode.Transform,
			ByteLength: mode.ByteLength,
			InputType:  mode.InputType,
		}
	}
	return out
}

// keyListVisibleHeight returns the number of visible key rows based on terminal height.
// Used by key list rendering, scroll handling, and key selection.
func (m Model) keyListVisibleHeight() int {
	h := m.windowBodyHeight() - 8 // Reserve lines for filter, scroll indicators, count, and spacing.
	if h < 3 {
		h = 3
	}
	return h
}

func scrollMoreAboveLine(count int) string {
	return scrollMoreLine(count, "▲", "above")
}

func scrollMoreBelowLine(count int) string {
	return scrollMoreLine(count, "▼", "below")
}

func scrollMoreLine(count int, arrow, direction string) string {
	if count <= 0 {
		return ""
	}
	return subtitleStyle.Render(fmt.Sprintf("  %s %d more %s", arrow, count, direction))
}

const keyAddressShortWidth = 23 // 10 leading chars + "..." + 10 trailing chars

func formatKeyAddress(address, keyType string, maxWidth int, useKeyTypeColor bool) string {
	width := keyAddressShortWidth
	if maxWidth > 0 && maxWidth < width {
		width = maxWidth
	}
	address = ellipsizeMiddle(address, width)
	if !useKeyTypeColor {
		return address
	}
	return styledAddress(address, keyType)
}

func keyAddressWidth(rowWidth int, prefix, mark, suffix string) int {
	if rowWidth <= 0 {
		return 0
	}
	width := rowWidth - len(prefix) - len(mark) - len(suffix)
	if width < 4 {
		return 4
	}
	return width
}

func ellipsizeMiddle(s string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width <= 3 {
		return string(runes[:width])
	}
	prefixLen := (width - 3) / 2
	suffixLen := width - 3 - prefixLen
	return string(runes[:prefixLen]) + "..." + string(runes[len(runes)-suffixLen:])
}

// detailsVisibleLines returns the number of visible lines for key details/TEAL view.
func (m Model) detailsVisibleLines() int {
	if m.height > 30 {
		return 12
	}
	if m.height < 20 {
		return 5
	}
	return 8
}

// getPlaceholderForType returns a placeholder string for the given parameter type.
func getPlaceholderForType(paramType string) string {
	switch paramType {
	case "address":
		return "(enter 58-char Algorand address)"
	case "address[]":
		return "(enter one address per line)"
	case "uint64":
		return "(enter number)"
	case "string":
		return "(enter value)"
	case "select":
		return "(select value)"
	default:
		return "(enter value)"
	}
}

// getFieldWidthForType returns the display width for an input field based on type.
func getFieldWidthForType(paramType string, maxLength int) int {
	switch paramType {
	case "address":
		return 60 // 58 chars + cursor + margin
	case "address[]":
		return 62
	case "uint64":
		return 20 // plenty for large numbers
	case "bytes":
		if maxLength > 0 {
			return maxLength + 2
		}
		return 66 // 32 bytes of hex plus cursor and margin
	case "string":
		if maxLength > 0 {
			return maxLength + 2
		}
		return 40
	case "select":
		return 40
	default:
		return 40
	}
}

// getMaxInputLengthForType returns the maximum input length for a parameter type.
func getMaxInputLengthForType(paramType string, maxLength int) int {
	switch paramType {
	case "address":
		return 58
	case "address[]":
		if maxLength > 0 {
			return maxLength
		}
		return 4096
	case "uint64":
		return 20 // Max uint64 is 20 digits
	case "bytes":
		if maxLength > 0 {
			return maxLength
		}
		return 4096
	case "string":
		if maxLength > 0 {
			return maxLength
		}
		return 256
	case "select":
		if maxLength > 0 {
			return maxLength
		}
		return 256
	default:
		return 256
	}
}

func isMultilineParamType(paramType string) bool {
	return paramType == "address[]"
}

func getFieldHeightForType(paramType string) int {
	if isMultilineParamType(paramType) {
		return 6
	}
	return 1
}
