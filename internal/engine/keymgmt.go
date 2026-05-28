// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

// ListKeyTypes returns available key types from Signer.
func (e *Engine) ListKeyTypes() ([]signerapi.KeyTypeInfo, error) {
	return e.ListKeyTypesWithContext(context.Background())
}

func (e *Engine) ListKeyTypesWithContext(ctx context.Context) ([]signerapi.KeyTypeInfo, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	resp, err := e.GetKeyTypesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch key types: %w", err)
	}
	return resp.KeyTypes, nil
}

// GenerateKey generates a new key on the Signer and refreshes the key cache.
func (e *Engine) GenerateKey(keyType string, params map[string]string) (*GenerateKeyResult, error) {
	return e.GenerateKeyWithContext(context.Background(), keyType, params)
}

func (e *Engine) GenerateKeyWithContext(ctx context.Context, keyType string, params map[string]string) (*GenerateKeyResult, error) {
	if !e.IsConnected() {
		return nil, ErrNotConnected
	}
	resp, err := e.AdminGenerateWithContext(ctx, keyType, params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	// Refresh signer cache to include the new key
	_, _ = e.RefreshKeysWithContext(ctx)
	return &GenerateKeyResult{Address: resp.Address, KeyType: resp.KeyType}, nil
}

// DeleteKey deletes a key from the Signer and refreshes the key cache.
func (e *Engine) DeleteKey(address string) error {
	return e.DeleteKeyWithContext(context.Background(), address)
}

func (e *Engine) DeleteKeyWithContext(ctx context.Context, address string) error {
	if !e.IsConnected() {
		return ErrNotConnected
	}
	if _, err := e.AdminDeleteKeyWithContext(ctx, address); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	// Refresh signer cache to reflect the deletion
	_, _ = e.RefreshKeysWithContext(ctx)
	return nil
}
