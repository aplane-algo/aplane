// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keys"
)

type IPCService struct {
	Service Service
	Logf    func(format string, args ...interface{})
}

func (s IPCService) ListKeys() ([]adminproto.KeyInfo, error) {
	return ProjectListKeys(s.Service.ListKeys())
}

func (s IPCService) GetKeyDetails(req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult {
	return ProjectKeyDetailsIPC(s.Service.GetKeyDetails(req.Address))
}

func (s IPCService) PrepareGenerateKey(req adminproto.PrepareGenerateKeyRequest) adminproto.PrepareGenerateKeyResult {
	prepared, err := s.Service.PrepareGenerateKey(req.KeyType, req.Parameters)
	return ProjectPrepareGenerateIPC(prepared, err)
}

func (s IPCService) GenerateKey(ctx context.Context, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult {
	genResult, err := s.Service.GenerateReviewedKey(ctx, req.KeyType, req.Parameters, ReviewedValues{
		Fingerprint:    req.ExpectedFingerprint,
		BoundaryDigest: req.ExpectedBoundaryDigest,
	})
	ipcResult := ProjectGenerateIPC(genResult, err)
	if ipcResult.Success {
		s.logGenerateKey(genResult)
	}
	return ipcResult
}

func (s IPCService) DeleteKey(ctx context.Context, req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult {
	delResult, err := s.Service.DeleteKey(ctx, req.Address)
	ipcResult := ProjectDeleteIPC(err)
	if ipcResult.Success {
		s.logf("deleted key via IPC: %s (moved to %s)", req.Address, delResult.DeletedPath)
	}
	return ipcResult
}

func (s IPCService) ImportKey(ctx context.Context, req adminproto.ImportKeyRequest) adminproto.ImportKeyResult {
	importResult, err := s.Service.ImportKey(ctx, req.KeyType, req.Mnemonic, req.Parameters)
	ipcResult := ProjectImportIPC(importResult, err)
	if ipcResult.Success {
		s.logf("imported %s key via IPC: %s", importResult.KeyType, importResult.Address)
	}
	return ipcResult
}

func (s IPCService) logGenerateKey(genResult *GenerateResult) {
	if genResult.IsWitnessKey {
		s.logf(
			"generated cosigner witness credential via IPC: %s (stored as %s%s)",
			genResult.Address,
			genResult.Address,
			keys.CosignerCredentialExtension,
		)
		return
	}
	if template, tmplErr := genericlsig.GetOrError(genResult.KeyType); tmplErr == nil {
		s.logf("generated %s via IPC: %s", template.DisplayName(), genResult.Address)
		return
	}
	s.logf("generated new %s key via IPC: %s", genResult.KeyType, genResult.Address)
}

func (s IPCService) logf(format string, args ...interface{}) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}
