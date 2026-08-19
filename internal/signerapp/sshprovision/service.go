// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshprovision

import (
	"context"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/tokenfile"
)

type AuditLogger interface {
	LogTokenProvisioned(identityID, sshFingerprint, remoteAddr string)
}

type Service struct {
	TokenRoot                       string
	RequestTokenProvisioning        func(requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error)
	RequestTokenProvisioningContext func(ctx context.Context, requestID, identityID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error)
	AuditLog                        AuditLogger
	Logf                            func(format string, args ...interface{})
	Now                             func() time.Time
}

func (s Service) Approve(identityID, sshFingerprint, remoteAddr string) (bool, error) {
	return s.ApproveContext(context.Background(), identityID, sshFingerprint, remoteAddr)
}

func (s Service) ApproveContext(ctx context.Context, identityID, sshFingerprint, remoteAddr string) (bool, error) {
	if s.RequestTokenProvisioningContext == nil && s.RequestTokenProvisioning == nil {
		return false, fmt.Errorf("token provisioning requester not configured")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	requestID := fmt.Sprintf("token-%d", now().UnixNano())
	if s.RequestTokenProvisioningContext != nil {
		return s.RequestTokenProvisioningContext(ctx, requestID, identityID, sshFingerprint, remoteAddr, 5*time.Minute)
	}
	return s.RequestTokenProvisioning(requestID, identityID, sshFingerprint, remoteAddr, 5*time.Minute)
}

func (s Service) Issue(identityID string) (string, error) {
	path := tokenfile.GetAPlaneTokenPathForRoot(s.TokenRoot)
	token, err := tokenfile.ReadToken(path)
	if err != nil {
		return "", fmt.Errorf("failed to load token: %w", err)
	}
	if token == "" {
		return "", fmt.Errorf("failed to load token: token file does not exist: %s", path)
	}
	return token, nil
}

func (s Service) AuditProvisioned(identityID, sshFingerprint, remoteAddr string) {
	if s.AuditLog != nil {
		s.AuditLog.LogTokenProvisioned(identityID, sshFingerprint, remoteAddr)
	}
	if s.Logf != nil {
		s.Logf("token provisioned for identity %q to %s (key: %s)", identityID, remoteAddr, sshFingerprint)
	}
}
