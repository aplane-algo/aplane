// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"fmt"
	"time"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

// wireApprovalCoordinator creates and installs an approval coordinator on the
// identity runtime. Must be called after the IPC server is available.
func (fs *Signer) wireApprovalCoordinator(ir *identity.Runtime) {
	identityID := ir.ID()
	coordinator := signerapproval.New(
		func() bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.HasClient(identityID)
		},
		func(msg *signerapproval.SignRequest) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendSignRequest(identityID, msg)
		},
		func(msg *signerapproval.SignRequestCanceled) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendSignRequestCanceled(identityID, msg)
		},
		func(msg *signerapproval.TokenProvisioningRequest) bool {
			hub := fs.adminHub()
			if hub == nil {
				return false
			}
			return hub.SendTokenProvisioningRequest(identityID, msg)
		},
	)
	ir.SetApprovalCoordinator(coordinator)
}

// Signer-level wrappers that route through the product identity runtime.
// These exist for call sites (IPC handlers, SSH callbacks) that don't yet
// resolve identity themselves.

func (fs *Signer) pendingSignCount() int {
	return fs.productIdentityRuntime().PendingSignCount()
}

func (fs *Signer) requestSigningApproval(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
	response, err := fs.requestSigningApprovalResponseContext(context.Background(), identityID, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
	if err != nil {
		return false, err
	}
	return response.Approved, nil
}

func (fs *Signer) requestSigningApprovalResponse(identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
	return fs.requestSigningApprovalResponseContext(context.Background(), identityID, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
}

func (fs *Signer) requestSigningApprovalContext(ctx context.Context, identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
	response, err := fs.requestSigningApprovalResponseContext(ctx, identityID, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
	if err != nil {
		return false, err
	}
	return response.Approved, nil
}

func (fs *Signer) requestSigningApprovalResponseContext(ctx context.Context, identityID, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error) {
	ir := fs.registry.Get(identityID)
	if ir == nil {
		return signerapproval.SignResponse{}, fmt.Errorf("identity not found: %s", identityID)
	}
	return ir.RequestSigningApprovalResponseContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
}

func (fs *Signer) failAllPendingApprovals(reason string) {
	fs.productIdentityRuntime().FailAllPendingApprovals(reason)
}

func (fs *Signer) requestTokenProvisioning(requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	return fs.requestTokenProvisioningContext(context.Background(), requestID, identityID, sshFingerprint, remoteAddr, timeout)
}

func (fs *Signer) requestTokenProvisioningContext(ctx context.Context, requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
	ir := fs.registry.Get(identityID)
	if ir == nil {
		return false, fmt.Errorf("identity not found: %s", identityID)
	}
	return ir.RequestTokenProvisioningContext(ctx, requestID, identityID, sshFingerprint, remoteAddr, timeout)
}
