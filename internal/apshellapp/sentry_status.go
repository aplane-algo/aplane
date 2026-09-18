// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

type SentryStatusRequest struct{}

type SentryStatusResult struct {
	engine.SentryStatusResult
	RenderLines []string `json:"-"`
}

// SentryStatus observes current routes without changing the active connection,
// client configuration, trust, credentials, or cached inventory.
func (a *App) SentryStatus(ctx context.Context, _ SentryStatusRequest) (*SentryStatusResult, error) {
	cfg, err := config.LoadConfig(a.DataDir)
	if err != nil {
		return nil, err
	}
	result := &SentryStatusResult{SentryStatusResult: a.eng.SentryStatus(ctx, cfg.Endpoints)}
	lines := []string{"Sentry status (point-in-time check)", "", "Connections"}
	if len(result.Connections) == 0 {
		lines = append(lines, "  No sentry connections configured; use sentry add.")
	}
	for _, connection := range result.Connections {
		lines = append(lines, fmt.Sprintf("  %s: %s", connection.Alias, connection.State), "    endpoint: "+connection.URL)
		for _, id := range connection.Witnesses {
			lines = append(lines, "    Witness Key ID: "+id)
		}
		if connection.Error != "" {
			lines = append(lines, "    reason: "+connection.Error)
		}
	}
	duplicateIDs := make([]string, 0, len(result.DuplicateRoutes))
	for id := range result.DuplicateRoutes {
		duplicateIDs = append(duplicateIDs, id)
	}
	sort.Strings(duplicateIDs)
	for _, id := range duplicateIDs {
		lines = append(lines, "  Duplicate witness route: "+id+" via "+strings.Join(result.DuplicateRoutes[id], ", "))
	}
	if result.DiscoveryError != "" {
		lines = append(lines, "  Route check: "+result.DiscoveryError)
	}
	lines = append(lines, "", "Account requirements")
	if result.AccountInventory != "available" {
		lines = append(lines, "  Unavailable: "+result.InventoryError)
	} else if len(result.Accounts) == 0 {
		lines = append(lines, "  No guarded accounts in the primary signer's current inventory.")
	}
	for _, account := range result.Accounts {
		label := account.Address
		if alias := a.eng.AliasCache.GetAliasForAddress(account.Address); alias != "" {
			label = alias + " (" + account.Address + ")"
		}
		lines = append(lines, fmt.Sprintf("  %s: %s", label, account.State))
		if account.WitnessKeyID != "" {
			lines = append(lines, "    Witness Key ID: "+account.WitnessKeyID)
		}
		if len(account.Routes) > 0 {
			lines = append(lines, "    routes: "+strings.Join(account.Routes, ", "))
		}
		if account.Error != "" {
			lines = append(lines, "    reason: "+account.Error)
		}
	}
	lines = append(lines, "", "Route availability does not confirm transaction policy, approval, or on-chain validity.")
	result.RenderLines = lines
	return result, nil
}
