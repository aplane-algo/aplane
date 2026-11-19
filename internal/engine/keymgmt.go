// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"slices"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func (e *Engine) ListKeyTypes(ctx context.Context) ([]signerapi.KeyTypeInfo, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	resp, err := e.GetKeyTypesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch key types: %w", err)
	}
	return resp.KeyTypes, nil
}

// KeyTypesForGeneration lists the signer's key types for generating keyType.
// A locked signer lists only its built-in key types, so when keyType is not
// among them and the signer reports itself locked, the answer is
// ErrSignerLockedForGeneration rather than a listing that reads as keyType
// being unknown.
func (e *Engine) KeyTypesForGeneration(ctx context.Context, keyType string) ([]signerapi.KeyTypeInfo, error) {
	keyTypes, err := e.ListKeyTypes(ctx)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(keyTypes, func(info signerapi.KeyTypeInfo) bool { return info.KeyType == keyType }) {
		return keyTypes, nil
	}
	locked, err := e.SignerLocked(ctx)
	if err != nil {
		return nil, fmt.Errorf("the signer does not list key type %s, and its lock state could not be read: %w", keyType, err)
	}
	if locked {
		return nil, ErrSignerLockedForGeneration
	}
	return keyTypes, nil
}

// SignerLocked reports whether the signer's /status says it is locked.
func (e *Engine) SignerLocked(ctx context.Context) (bool, error) {
	if !e.IsConnected() {
		return false, ErrNotConnected
	}
	status, err := e.GetSignerStatusWithContext(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to fetch signer status: %w", err)
	}
	return status.SignerLocked, nil
}

func (e *Engine) GenerateKey(ctx context.Context, keyType string, params map[string]string) (*GenerateKeyResult, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	// Canonicalize the key type and resolve any address[] creation params (e.g. a
	// allowlist's "recipients") before handing off to the signer, which has no
	// alias/set knowledge. Done here — not in the REPL layer — so REPL, JS, and
	// MCP callers all behave identically.
	keyType = keytypecatalog.Canonicalize(keyType)
	if len(params) > 0 {
		keyTypes, err := e.KeyTypesForGeneration(ctx, keyType)
		if err != nil {
			return nil, err
		}
		params, err = expandGenerateAddressListParams(keyType, params, keyTypes, e.NewAddressResolver())
		if err != nil {
			return nil, err
		}
	}
	return e.generateResolvedKey(ctx, keyType, params)
}

// GenerateKeyFromLiterals generates a key from values that are already literal.
// It skips alias and set expansion, so a validated boundary file's recipients
// cannot be reinterpreted against this client's address book.
func (e *Engine) GenerateKeyFromLiterals(ctx context.Context, keyType string, params map[string]string) (*GenerateKeyResult, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	return e.generateResolvedKey(ctx, keytypecatalog.Canonicalize(keyType), params)
}

func (e *Engine) generateResolvedKey(ctx context.Context, keyType string, params map[string]string) (*GenerateKeyResult, error) {
	resp, err := e.AdminGenerateWithContext(ctx, keyType, params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	result := &GenerateKeyResult{Address: resp.Address, KeyType: resp.KeyType, Parameters: resp.Parameters, Warnings: resp.Warnings}
	// Refresh signer cache to include the new key
	keys, refreshErr := e.RefreshKeys(ctx)
	if refreshErr != nil {
		return result, nil
	}
	for _, key := range keys {
		if key.Address == resp.Address {
			result.CosignerKeyID, result.InventoryRead = key.CosignerKeyID, true
			break
		}
	}
	return result, nil
}

func (e *Engine) DeleteKey(ctx context.Context, address string) error {
	if !e.IsConnected() {
		return ErrNotConnected
	}
	if _, err := e.AdminDeleteKeyWithContext(ctx, address); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	// Refresh signer cache to reflect the deletion
	_, _ = e.RefreshKeys(ctx)
	return nil
}
