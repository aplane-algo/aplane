// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"fmt"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/version"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func (s Service) Health(ir *productruntime.Runtime, sshEnabled, ipcEnabled bool) *signerapi.HealthResponse {
	status := "healthy"
	locked := false
	readyForSigning := false
	if ir == nil {
		status = "degraded"
	} else {
		locked = !ir.IsUnlocked()
		readyForSigning = ir.IsUnlocked()
	}

	return &signerapi.HealthResponse{
		Status:          status,
		Service:         "Signer",
		ProtocolVersion: signerapi.CurrentProtocolVersion(),
		BuildVersion:    version.String(),
		SignerLocked:    locked,
		ReadyForSigning: readyForSigning,
		SSHEnabled:      sshEnabled,
		IPCEnabled:      ipcEnabled,
		Warnings:        s.publicStoreHealthWarnings(ir),
	}
}

func (s Service) Status(ir *productruntime.Runtime) *signerapi.StatusResponse {
	state := "unknown"
	locked := true
	readyForSigning := false
	keyCount := 0
	keysetRevision := uint64(0)
	approvalWaitSeconds := int64(0)
	nodeRole := ""

	if ir != nil {
		nodeRole = string(ir.NodeRole())
		state = ir.GetState().String()
		locked = !ir.IsUnlocked()
		readyForSigning = ir.IsUnlocked()
		keyCount = ir.KeyCount()
		keysetRevision = ir.KeysetRevision()
		approvalWaitSeconds = int64(ir.Config().ApprovalWait() / time.Second)
	}

	return &signerapi.StatusResponse{
		NodeRole:            nodeRole,
		ProtocolVersion:     signerapi.CurrentProtocolVersion(),
		BuildVersion:        version.String(),
		State:               state,
		SignerLocked:        locked,
		ReadyForSigning:     readyForSigning,
		KeyCount:            keyCount,
		KeysetRevision:      keysetRevision,
		ApprovalWaitSeconds: approvalWaitSeconds,
		Warnings:            storeHealthWarnings(ir),
	}
}

// storeHealthCacheTTL bounds how often the unauthenticated health endpoint
// inspects the store: it lists and stats every deleted-archive member.
const storeHealthCacheTTL = 5 * time.Second

// StoreHealthCache reuses the health endpoint's store inspection for
// storeHealthCacheTTL per active generation.
type StoreHealthCache struct {
	mu            sync.Mutex
	now           func() time.Time // tests may replace the clock
	generationDir string
	checkedAt     time.Time
	warnings      []string
}

func (c *StoreHealthCache) get(generationDir string, compute func() []string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	if c.generationDir == generationDir && !c.checkedAt.IsZero() && now.Sub(c.checkedAt) < storeHealthCacheTTL {
		return c.warnings
	}
	c.generationDir, c.checkedAt, c.warnings = generationDir, now, compute()
	return c.warnings
}

// publicStoreHealthWarnings is the unauthenticated form of the store
// warnings: cached, and without error detail such as store paths, which the
// authenticated /status response carries.
func (s Service) publicStoreHealthWarnings(ir *productruntime.Runtime) []string {
	if ir == nil {
		return nil
	}
	active, err := ir.ActivePaths()
	if err != nil {
		return nil
	}
	compute := func() []string {
		usage, err := genstore.InspectDeletedArchive(active)
		if err != nil {
			return []string{"deleted archive health check failed; authenticated /status has details"}
		}
		return deletedArchiveWarnings(usage)
	}
	if s.Deps.StoreHealth == nil {
		return compute()
	}
	return s.Deps.StoreHealth.get(active.Dir(), compute)
}

func deletedArchiveWarnings(usage genstore.DeletedArchiveUsage) []string {
	if usage.Warning() {
		return []string{fmt.Sprintf(
			"deleted archive emergency reserve is consumed (%d entries, %d encoded bytes); authenticated prune is required",
			usage.Entries, usage.EncodedBytes,
		)}
	}
	return nil
}

func storeHealthWarnings(ir *productruntime.Runtime) []string {
	if ir == nil {
		return nil
	}
	active, err := ir.ActivePaths()
	if err != nil {
		return nil
	}
	usage, err := genstore.InspectDeletedArchive(active)
	if err != nil {
		return []string{fmt.Sprintf("deleted archive health check failed: %v", err)}
	}
	return deletedArchiveWarnings(usage)
}
