// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package tui

// Helper functions for key type options and input field configuration.

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

// getKeyTypeOptions returns a list of key type display strings for UI selection.
// Uses keymgmt.GetValidKeyTypes() which returns versioned types (e.g., "falcon1024-v1").
func getKeyTypeOptions() []string {
	types := keymgmt.GetValidKeyTypes()
	options := make([]string, len(types))
	for i, keyType := range types {
		meta, err := algorithm.GetMetadata(keyType)
		if err == nil && meta != nil {
			options[i] = fmt.Sprintf("%s (%d words)", keyType, meta.MnemonicWordCount())
		} else {
			options[i] = keyType
		}
	}
	return options
}

// getKeyTypeOptionsWithDescription returns key type options with descriptions for generate form.
// Includes both cryptographic key types (versioned) and generic LogicSig templates.
func getKeyTypeOptionsWithDescription() []string {
	// Get cryptographic key types from keymgmt (returns versioned types)
	types := keymgmt.GetValidKeyTypes()
	options := make([]string, 0, len(types)+genericlsig.Count())

	for _, keyType := range types {
		meta, err := algorithm.GetMetadata(keyType)
		if err == nil && meta != nil {
			// Add description based on whether it requires LogicSig
			if meta.RequiresLogicSig() {
				options = append(options, fmt.Sprintf("%s (post-quantum)", keyType))
			} else {
				options = append(options, fmt.Sprintf("%s (standard Algorand)", keyType))
			}
		} else {
			options = append(options, keyType)
		}
	}

	// Add generic LogicSig templates from registry
	for _, template := range genericlsig.GetAll() {
		options = append(options, fmt.Sprintf("%s (generic lsig)", template.DisplayName()))
	}

	return options
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

// getKeyTypeByIndex returns the key type identifier for the given index.
// Handles both cryptographic key types (versioned) and generic LogicSig templates.
func getKeyTypeByIndex(index int) string {
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
	return len(keymgmt.GetValidKeyTypes()) + genericlsig.Count()
}

// getExpectedWordCount returns the expected mnemonic word count for a key type index.
func getExpectedWordCount(keyTypeIndex int) int {
	keyType := getKeyTypeByIndex(keyTypeIndex)
	if keyType == "" {
		return 25 // default for ed25519
	}
	meta, err := algorithm.GetMetadata(keyType)
	if err == nil && meta != nil {
		return meta.MnemonicWordCount()
	}
	return 25 // default
}

// getPlaceholderForType returns a placeholder string for the given parameter type.
func getPlaceholderForType(paramType string) string {
	switch paramType {
	case "address":
		return "(enter 58-char Algorand address)"
	case "uint64":
		return "(enter number)"
	case "string":
		return "(enter value)"
	default:
		return "(enter value)"
	}
}

// getFieldWidthForType returns the display width for an input field based on type.
func getFieldWidthForType(paramType string, maxLength int) int {
	switch paramType {
	case "address":
		return 60 // 58 chars + cursor + margin
	case "uint64":
		return 20 // plenty for large numbers
	case "string":
		if maxLength > 0 {
			return maxLength + 2
		}
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
	case "uint64":
		return 20 // Max uint64 is 20 digits
	case "string":
		if maxLength > 0 {
			return maxLength
		}
		return 256
	default:
		return 256
	}
}
