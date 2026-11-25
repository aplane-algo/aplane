// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"fmt"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/version"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func (s Service) Health(ir *productruntime.Runtime) *signerapi.HealthResponse {
	status := "healthy"
	locked := true
	if ir == nil {
		status = "degraded"
	} else {
		locked = !ir.IsUnlocked()
	}

	return &signerapi.HealthResponse{
		Status:       status,
		Service:      "Signer",
		BuildVersion: version.String(),
		SignerLocked: locked,
		Warnings:     s.storeHealthWarnings(ir, publicInspectionFailure),
	}
}

func (s Service) Status(ir *productruntime.Runtime) *signerapi.StatusResponse {
	state := "unknown"
	locked := true
	keyCount := 0
	keysetRevision := uint64(0)
	approvalWaitSeconds := int64(0)
	nodeRole := ""

	if ir != nil {
		nodeRole = string(ir.NodeRole())
		state = ir.GetState().String()
		locked = !ir.IsUnlocked()
		keyCount = ir.KeyCount()
		keysetRevision = ir.KeysetRevision()
		approvalWaitSeconds = int64(ir.Config().ApprovalWait() / time.Second)
	}

	return &signerapi.StatusResponse{
		NodeRole:            nodeRole,
		BuildVersion:        version.String(),
		State:               state,
		SignerLocked:        locked,
		KeyCount:            keyCount,
		KeysetRevision:      keysetRevision,
		ApprovalWaitSeconds: approvalWaitSeconds,
		Warnings:            s.statusWarnings(ir),
		Notes:               statusNotes(ir),
		Rotating:            rotatingStatuses(ir),
	}
}

// rotatingStatuses is the per-account rotating status from the last pass.
func rotatingStatuses(ir *productruntime.Runtime) []signerapi.RotatingAccountStatus {
	if ir == nil {
		return nil
	}
	return ir.RotatingAccountStatuses()
}

// statusWarnings are the authenticated status warnings: store health plus
// any rotating account alerts and policy admission alerts. Both name
// accounts or policy content, so they never appear on the unauthenticated
// health endpoint.
func (s Service) statusWarnings(ir *productruntime.Runtime) []string {
	warnings := s.storeHealthWarnings(ir, inspectionFailure)
	if ir != nil {
		warnings = append(warnings, ir.StatusAlerts()...)
	}
	return warnings
}

// statusNotes are informational lines that need no action.
func statusNotes(ir *productruntime.Runtime) []string {
	if ir == nil {
		return nil
	}
	return ir.RotatingNotes()
}

// storeHealthCacheTTL bounds how often the health and status endpoints inspect
// the store: each inspection lists and stats every deleted-archive member.
const storeHealthCacheTTL = 5 * time.Second

// StoreHealthCache reuses the last store inspection for storeHealthCacheTTL
// per active generation, for the health and status endpoints alike.
type StoreHealthCache struct {
	mu            sync.Mutex
	now           func() time.Time // tests may replace the clock
	generationDir string
	checkedAt     time.Time
	usage         genstore.DeletedArchiveUsage
	err           error
}

func (c *StoreHealthCache) inspect(active storepaths.GenPaths) (genstore.DeletedArchiveUsage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	if c.generationDir != active.Dir() || c.checkedAt.IsZero() || now.Sub(c.checkedAt) >= storeHealthCacheTTL {
		c.generationDir, c.checkedAt = active.Dir(), now
		c.usage, c.err = genstore.InspectDeletedArchive(active)
	}
	return c.usage, c.err
}

// publicInspectionFailure is the unauthenticated form of a failed inspection,
// without detail such as store paths, which inspectionFailure carries.
func publicInspectionFailure(error) string {
	return "deleted archive health check failed; authenticated /status has details"
}

func inspectionFailure(err error) string {
	return fmt.Sprintf("deleted archive health check failed: %v", err)
}

// storeHealthWarnings are the store's warnings, with a failed inspection worded
// by failure.
func (s Service) storeHealthWarnings(ir *productruntime.Runtime, failure func(error) string) []string {
	if ir == nil {
		return nil
	}
	active, err := ir.ActivePaths()
	if err != nil {
		return nil
	}
	inspect := genstore.InspectDeletedArchive
	if s.Deps.StoreHealth != nil {
		inspect = s.Deps.StoreHealth.inspect
	}
	usage, err := inspect(active)
	switch {
	case err != nil:
		return []string{failure(err)}
	case usage.Warning():
		return []string{fmt.Sprintf(
			"deleted archive emergency reserve is consumed (%d entries, %d encoded bytes); authenticated prune is required",
			usage.Entries, usage.EncodedBytes,
		)}
	}
	return nil
}
