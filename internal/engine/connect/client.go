// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

func (s *ConnectionState) signerClient() (*signerclient.Client, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.SignerClient == nil {
		return nil, fmt.Errorf("not connected to Signer")
	}
	if s.SignerProgressOut != nil && s.SignerClient.ProgressOut == nil {
		s.SignerClient.ProgressOut = s.SignerProgressOut
	}
	return s.SignerClient, nil
}

// GetKeys fetches the current signer key inventory.
func (s *ConnectionState) GetKeys() (*signerapi.KeysResult, error) {
	return s.GetKeysWithContext(context.Background())
}

func (s *ConnectionState) GetKeysWithContext(ctx context.Context) (*signerapi.KeysResult, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.GetKeysWithContext(ctx)
}

// GetKeyTypes fetches supported key types from Signer.
func (s *ConnectionState) GetKeyTypes() (*signerapi.KeyTypesResponse, error) {
	return s.GetKeyTypesWithContext(context.Background())
}

func (s *ConnectionState) GetKeyTypesWithContext(ctx context.Context) (*signerapi.KeyTypesResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.GetKeyTypesWithContext(ctx)
}

// GetSignerStatus fetches authenticated signer status and keyset revision from Signer.
func (s *ConnectionState) GetSignerStatus() (*signerapi.StatusResponse, error) {
	return s.GetSignerStatusWithContext(context.Background())
}

func (s *ConnectionState) GetSignerStatusWithContext(ctx context.Context) (*signerapi.StatusResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.GetStatusWithContext(ctx)
}

// AdminGenerate requests key generation from Signer.
func (s *ConnectionState) AdminGenerate(keyType string, params map[string]string) (*signerapi.AdminGenerateResponse, error) {
	return s.AdminGenerateWithContext(context.Background(), keyType, params)
}

func (s *ConnectionState) AdminGenerateWithContext(ctx context.Context, keyType string, params map[string]string) (*signerapi.AdminGenerateResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.AdminGenerateWithContext(ctx, keyType, params)
}

// AdminDeleteKey requests key deletion from Signer.
func (s *ConnectionState) AdminDeleteKey(address string) (*signerapi.AdminDeleteResponse, error) {
	return s.AdminDeleteKeyWithContext(context.Background(), address)
}

func (s *ConnectionState) AdminDeleteKeyWithContext(ctx context.Context, address string) (*signerapi.AdminDeleteResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.AdminDeleteKeyWithContext(ctx, address)
}

// RequestGroupPlan sends group planning requests to Signer.
func (s *ConnectionState) RequestGroupPlan(requests []signerapi.SignRequest) (*signerapi.GroupPlanResponse, error) {
	return s.RequestGroupPlanWithContext(context.Background(), requests)
}

func (s *ConnectionState) RequestGroupPlanWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupPlanResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestGroupPlanWithContext(ctx, requests)
}

// RequestGroupSimulate sends group simulation requests to Signer.
func (s *ConnectionState) RequestGroupSimulate(requests []signerapi.SignRequest) (*signerapi.GroupSimulateResponse, error) {
	return s.RequestGroupSimulateWithContext(context.Background(), requests)
}

func (s *ConnectionState) RequestGroupSimulateWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupSimulateResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestGroupSimulateWithContext(ctx, requests)
}

// RequestGroupSign sends group signing requests to Signer.
func (s *ConnectionState) RequestGroupSign(requests []signerapi.SignRequest) (*signerapi.GroupSignResponse, error) {
	return s.RequestGroupSignWithContext(context.Background(), requests)
}

func (s *ConnectionState) RequestGroupSignWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupSignResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestGroupSignWithContext(ctx, requests)
}

// RequestComponentSign sends a component-signing request to Signer.
func (s *ConnectionState) RequestComponentSign(req signerapi.ComponentSignRequest) (*signerapi.ComponentSignResponse, error) {
	return s.RequestComponentSignWithContext(context.Background(), req)
}

func (s *ConnectionState) RequestComponentSignWithContext(ctx context.Context, req signerapi.ComponentSignRequest) (*signerapi.ComponentSignResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestComponentSignWithContext(ctx, req)
}

// RequestAttestedAssemble sends an attested assembly request to Signer.
func (s *ConnectionState) RequestAttestedAssemble(req signerapi.AttestedAssemblyRequest) (*signerapi.AttestedAssemblyResponse, error) {
	return s.RequestAttestedAssembleWithContext(context.Background(), req)
}

func (s *ConnectionState) RequestAttestedAssembleWithContext(ctx context.Context, req signerapi.AttestedAssemblyRequest) (*signerapi.AttestedAssemblyResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestAttestedAssembleWithContext(ctx, req)
}
