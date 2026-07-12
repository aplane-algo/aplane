// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

// Shared resolution of address-list creation parameters for `generate`.
// Lives in the engine (not the REPL/cmdspec UI layer) so every caller — REPL,
// JS, MCP — that generates a key through the engine gets identical behavior,
// and so the engine does not depend on UI parsing packages.

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

// addressListResolver resolves alias/@set inputs to concrete addresses.
type addressListResolver interface {
	ResolveList(inputs []string) ([]string, error)
}

// expandGenerateAddressListParams resolves any address[]-typed creation params
// (for example an allowlist LogicSig's "recipients") for the given key type:
// each entry is resolved through the resolver — so aliases and @sets become
// concrete addresses — and the result is sorted so the generated key is
// independent of the order the caller supplied. Params that are not address[]
// for this key type pass through unchanged.
func expandGenerateAddressListParams(
	keyType string,
	params map[string]string,
	keyTypes []signerapi.KeyTypeInfo,
	resolver addressListResolver,
) (map[string]string, error) {
	if len(params) == 0 {
		return params, nil
	}

	addressListParams, err := addressListCreationParams(keyType, keyTypes)
	if err != nil {
		return nil, err
	}
	if len(addressListParams) == 0 {
		return params, nil
	}

	expanded := make(map[string]string, len(params))
	for name, value := range params {
		if slices.Contains(addressListParams, name) {
			parts := splitAddressListParam(value)
			addresses, err := resolver.ResolveList(parts)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve %s %q: %w", name, value, err)
			}
			sort.Strings(addresses)
			expanded[name] = strings.Join(addresses, ",")
			continue
		}
		expanded[name] = value
	}

	return expanded, nil
}

func splitAddressListParam(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func addressListCreationParams(keyType string, keyTypes []signerapi.KeyTypeInfo) ([]string, error) {
	for _, kt := range keyTypes {
		if kt.KeyType != keyType {
			continue
		}
		var names []string
		for _, param := range kt.CreationParams {
			if param.Type == "address[]" {
				names = append(names, param.Name)
			}
		}
		return names, nil
	}
	return nil, fmt.Errorf("unknown key type: %s", keyType)
}
