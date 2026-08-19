// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"time"

	"github.com/aplane-algo/aplane/internal/productmode"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/version"
)

func (s Service) Health(ir *identity.Runtime, sshEnabled, ipcEnabled bool) *signerapi.HealthResponse {
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
	}
}

func (s Service) Status(ir *identity.Runtime) *signerapi.StatusResponse {
	state := "unknown"
	locked := true
	readyForSigning := false
	keyCount := 0
	keysetRevision := uint64(0)
	approvalWaitSeconds := int64(0)
	identityID := ""
	nodeRole := ""

	if ir != nil {
		identityID = productmode.IdentityID
		nodeRole = string(ir.NodeRole())
		state = ir.GetState().String()
		locked = !ir.IsUnlocked()
		readyForSigning = ir.IsUnlocked()
		keyCount = ir.KeyCount()
		keysetRevision = ir.KeysetRevision()
		approvalWaitSeconds = int64(ir.Config().ApprovalWait() / time.Second)
	}

	return &signerapi.StatusResponse{
		IdentityID:          identityID,
		NodeRole:            nodeRole,
		ProtocolVersion:     signerapi.CurrentProtocolVersion(),
		BuildVersion:        version.String(),
		State:               state,
		SignerLocked:        locked,
		ReadyForSigning:     readyForSigning,
		KeyCount:            keyCount,
		KeysetRevision:      keysetRevision,
		ApprovalWaitSeconds: approvalWaitSeconds,
	}
}
