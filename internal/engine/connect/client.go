// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package connect

import (
	"context"
	"errors"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// ErrNotConnected is returned by every signer request made with no signer
// client, for example after the tunnel closed.
var ErrNotConnected = errors.New("not connected to Signer")

func (s *ConnectionState) signerClient() (*signerclient.Client, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.SignerClient == nil {
		return nil, ErrNotConnected
	}
	return s.SignerClient, nil
}

func (s *ConnectionState) GetKeysWithContext(ctx context.Context) (*signerclient.KeysResult, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.GetKeysWithContext(ctx)
}

func (s *ConnectionState) GetKeyTypesWithContext(ctx context.Context) (*signerapi.KeyTypesResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.GetKeyTypesWithContext(ctx)
}

func (s *ConnectionState) GetSignerStatusWithContext(ctx context.Context) (*signerapi.StatusResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.GetStatusWithContext(ctx)
}

func (s *ConnectionState) AdminGenerateWithContext(ctx context.Context, keyType string, params map[string]string) (*signerapi.AdminGenerateResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.AdminGenerateWithContext(ctx, keyType, params)
}

func (s *ConnectionState) AdminDeleteKeyWithContext(ctx context.Context, address string) (*signerapi.AdminDeleteResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.AdminDeleteKeyWithContext(ctx, address)
}

// RotatingRecoverWithContext starts or cancels a rotating account's stage
// recovery on Signer.
func (s *ConnectionState) RotatingRecoverWithContext(ctx context.Context, req signerapi.RotatingRecoverRequest) (*signerapi.RotatingRecoverResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RotatingRecoverWithContext(ctx, req)
}

func (s *ConnectionState) RequestGroupPlanWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupPlanResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestGroupPlanWithContext(ctx, requests)
}

func (s *ConnectionState) RequestGroupSignWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupSignResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestGroupSignWithContext(ctx, requests)
}

func (s *ConnectionState) RequestComponentsWithContext(ctx context.Context, req signerapi.ComponentRequest) (*signerapi.ComponentResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestComponentsWithContext(ctx, req)
}

func (s *ConnectionState) RequestAssembleWithContext(ctx context.Context, req signerapi.AssemblyRequest) (*signerapi.AssemblyResponse, error) {
	client, err := s.signerClient()
	if err != nil {
		return nil, err
	}
	return client.RequestAssembleWithContext(ctx, req)
}
