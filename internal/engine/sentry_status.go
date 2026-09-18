// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine/guarded"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// SentryStatusResult retains unavailable account inventory separately from an
// empty, successfully read inventory. Neither the inventory nor routes persist.
type SentryStatusResult struct {
	guarded.RouteStatus
	AccountInventory string `json:"account_inventory"`
	InventoryError   string `json:"inventory_error,omitempty"`
}

func (e *Engine) SentryStatus(ctx context.Context, registry config.ClientEndpointRegistry) SentryStatusResult {
	result := SentryStatusResult{AccountInventory: "unavailable"}
	var keys []signerapi.KeyInfo
	if !e.IsConnected() {
		result.InventoryError = "primary signer disconnected; connect it to inspect account requirements"
	} else {
		inventoryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		inventory, err := e.GetKeysWithContext(inventoryCtx)
		cancel()
		switch {
		case err != nil:
			result.InventoryError = err.Error()
		case inventory.Locked:
			result.InventoryError = "primary signer locked"
		default:
			result.AccountInventory = "available"
			keys = inventory.Keys
		}
	}
	inspector := guarded.New(guarded.Deps{Conn: e.Connection, EndpointRegistry: registry})
	result.RouteStatus = inspector.InspectRoutes(ctx, keys)
	return result
}
