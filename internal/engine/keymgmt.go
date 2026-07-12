// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/signerapi"
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
		keyTypes, err := e.ListKeyTypes(ctx)
		if err != nil {
			return nil, err
		}
		params, err = expandGenerateAddressListParams(keyType, params, keyTypes, e.NewAddressResolver())
		if err != nil {
			return nil, err
		}
	}
	resp, err := e.AdminGenerateWithContext(ctx, keyType, params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	// Refresh signer cache to include the new key
	_, _ = e.RefreshKeys(ctx)
	return &GenerateKeyResult{Address: resp.Address, KeyType: resp.KeyType}, nil
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
