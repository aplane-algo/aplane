// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/version"
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
		Warnings:        storeHealthWarnings(ir),
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
	if usage.Warning() {
		return []string{fmt.Sprintf(
			"deleted archive emergency reserve is consumed (%d entries, %d encoded bytes); authenticated prune is required",
			usage.Entries, usage.EncodedBytes,
		)}
	}
	return nil
}
