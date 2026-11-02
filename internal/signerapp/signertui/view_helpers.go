// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

// Helper functions for key type options and input field configuration.

import (
	"fmt"
	"slices"
	"strings"
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
	slices.SortStableFunc(serverKeyTypes.items, func(a, b protocol.KeyTypeInfo) int {
		return compareKeyTypesForSelection(a.KeyType, b.KeyType)
	})
}

// isNativeKeyType reports whether keyType is a protocol-native scheme, named
// bare (ed25519, falcon1024) rather than publisher.family.vN.
func isNativeKeyType(keyType string) bool {
	return !strings.Contains(keyType, ".")
}

// compareKeyTypesForSelection orders key type pickers in two clusters: the
// protocol-native key types first, then every published key type, each
// cluster alphabetical.
func compareKeyTypesForSelection(a, b string) int {
	if aNative, bNative := isNativeKeyType(a), isNativeKeyType(b); aNative != bNative {
		if aNative {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func sortKeyTypesForSelection(keyTypes []string) []string {
	slices.SortStableFunc(keyTypes, compareKeyTypesForSelection)
	return keyTypes
}

// nativeKeyTypeCount is how many of keyTypes, in selection order, belong to
// the native cluster at the top.
func nativeKeyTypeCount(keyTypes []string) int {
	count := 0
	for _, keyType := range keyTypes {
		if isNativeKeyType(keyType) {
			count++
		}
	}
	return count
}

// separateKeyTypeClusters inserts a blank row between the native and the
// published key type clusters when both are present, and returns the rows
// with the selected index moved to match.
func separateKeyTypeClusters(rows []string, nativeCount, selected int) ([]string, int) {
	if nativeCount <= 0 || nativeCount >= len(rows) {
		return rows, selected
	}
	out := make([]string, 0, len(rows)+1)
	out = append(out, rows[:nativeCount]...)
	out = append(out, "")
	out = append(out, rows[nativeCount:]...)
	if selected >= nativeCount {
		selected++
	}
	return out, selected
}

// compiledGenerateKeyTypes is the generate list from the compiled registries,
// used before the signer has sent its own list.
func compiledGenerateKeyTypes() []string {
	types := append([]string(nil), keymgmt.GetValidKeyTypes()...)
	for _, template := range genericlsig.GetAll() {
		types = append(types, template.KeyType())
	}
	return sortKeyTypesForSelection(types)
}

// compiledImportKeyTypes is the mnemonic import list from the compiled
// registries, used before the signer has sent its own list.
func compiledImportKeyTypes() []string {
	return sortKeyTypesForSelection(append([]string(nil), keymgmt.GetMnemonicImportKeyTypesWithActivated(nil)...))
}

// generateKeyTypeIDs is the generate list's key types in display order.
func generateKeyTypeIDs() []string {
	if types := getServerKeyTypes(); len(types) > 0 {
		ids := make([]string, len(types))
		for i, info := range types {
			ids[i] = info.KeyType
		}
		return ids
	}
	return compiledGenerateKeyTypes()
}

// importKeyTypeIDs is the mnemonic import list's key types in display order.
func importKeyTypeIDs() []string {
	if types := getServerImportKeyTypes(); len(types) > 0 {
		ids := make([]string, len(types))
		for i, info := range types {
			ids[i] = info.KeyType
		}
		return ids
	}
	return compiledImportKeyTypes()
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

// getKeyTypeOptions returns the mnemonic import key type display strings, in
// selection order (native key types first, then published ones).
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

	types := compiledImportKeyTypes()
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

// getGenerateKeyTypeOptions returns key type options for the generate form,
// in selection order: native key types first, then published key types and
// generic LogicSig templates.
func getGenerateKeyTypeOptions() []string {
	if types := getServerKeyTypes(); len(types) > 0 {
		options := make([]string, len(types))
		for i, info := range types {
			options[i] = displayKeyType(info.KeyType)
		}
		return options
	}

	types := compiledGenerateKeyTypes()
	options := make([]string, len(types))
	for i, keyType := range types {
		options[i] = displayKeyType(keyType)
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
	types := compiledImportKeyTypes()
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

	types := compiledGenerateKeyTypes()
	if index >= 0 && index < len(types) {
		return types[index]
	}
	return ""
}

// getKeyTypeCount returns the total number of key types (cryptographic + generic lsig).
func getKeyTypeCount() int {
	if types := getServerKeyTypes(); len(types) > 0 {
		return len(types)
	}
	return len(compiledGenerateKeyTypes())
}

func getImportKeyTypeCount() int {
	if types := getServerImportKeyTypes(); len(types) > 0 {
		return len(types)
	}
	return len(compiledImportKeyTypes())
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
	reservedLines := 8 // Reserve lines for filter, scroll indicators, count, and spacing.
	h := m.windowBodyHeight() - reservedLines
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
