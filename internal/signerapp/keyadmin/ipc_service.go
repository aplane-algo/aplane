// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
)

type IPCService struct {
	Service             Service
	GenerateGenericLSig GenerateGenericLSigFunc
	Logf                func(format string, args ...interface{})
}

func (s IPCService) ListKeys(ir *productruntime.Runtime) ([]adminproto.KeyInfo, error) {
	return ProjectListKeys(s.Service.ListKeys(ir))
}

func (s IPCService) GetKeyDetails(ir *productruntime.Runtime, req adminproto.GetKeyDetailsRequest) adminproto.GetKeyDetailsResult {
	return ProjectKeyDetailsIPC(s.Service.GetKeyDetails(ir, req.Address))
}

func (s IPCService) GenerateKey(ctx context.Context, ir *productruntime.Runtime, req adminproto.GenerateKeyRequest) adminproto.GenerateKeyResult {
	genResult, err := s.Service.GenerateKey(ctx, ir, req.KeyType, req.Parameters, s.GenerateGenericLSig)
	ipcResult := ProjectGenerateIPC(genResult, err)
	if !ipcResult.Success {
		return ipcResult
	}

	s.logGenerateKey(genResult)
	return ipcResult
}

func (s IPCService) DeleteKey(ir *productruntime.Runtime, req adminproto.DeleteKeyRequest) adminproto.DeleteKeyResult {
	delResult, err := s.Service.DeleteKey(ir, req.Address)
	ipcResult := ProjectDeleteIPC(err)
	if !ipcResult.Success {
		return ipcResult
	}

	if delResult != nil {
		s.logf("deleted key via IPC: %s (moved to %s)", req.Address, delResult.DeletedPath)
	}
	return ipcResult
}

func (s IPCService) ImportKey(ir *productruntime.Runtime, req adminproto.ImportKeyRequest) adminproto.ImportKeyResult {
	importResult, err := s.Service.ImportKey(ir, req.KeyType, req.Mnemonic, req.Parameters)
	ipcResult := ProjectImportIPC(importResult, err)
	if !ipcResult.Success {
		return ipcResult
	}

	if importResult != nil {
		s.logf("imported %s key via IPC: %s", keytypefmt.Display(importResult.KeyType), importResult.Address)
	}
	return ipcResult
}

func (s IPCService) logGenerateKey(genResult *GenerateResult) {
	if genResult == nil {
		return
	}
	if genResult.IsWitnessKey {
		s.logf(
			"generated sentry witness credential via IPC: %s (stored as %s%s)",
			genResult.Address,
			genResult.Address,
			keys.SentryCredentialExtension,
		)
		return
	}
	if template, tmplErr := genericlsig.GetOrError(genResult.KeyType); tmplErr == nil {
		s.logf("generated %s via IPC: %s", template.DisplayName(), genResult.Address)
		return
	}
	s.logf("generated new %s key via IPC: %s", keytypefmt.Display(genResult.KeyType), genResult.Address)
}

func (s IPCService) logf(format string, args ...interface{}) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}
