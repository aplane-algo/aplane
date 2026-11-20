// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/engine/connect"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// ConnectWithTunnel establishes an SSH tunnel connection authenticated by the
// client's enrolled key.
// This method handles the tunnel setup and returns the result.
// hostKeyApproval is called for TOFU when connecting to an unknown server (can be nil to reject unknown hosts).
func (e *Core) ConnectWithTunnel(ctx context.Context, target string, host string, sshPort int, identityFile string, knownHostsPath string, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onDisconnect func()) (*ConnectionResult, error) {
	result, err := e.Connection.ConnectWithTunnel(
		ctx, target, host, sshPort, identityFile, knownHostsPath, hostKeyApproval,
		e.populateSignerCache,
		e.handleConnectionClosed(onDisconnect),
	)
	if err != nil {
		if errors.Is(err, connect.ErrAlreadyConnected) {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyConnected, e.GetConnectionTarget())
		}
		return nil, err
	}
	return &ConnectionResult{
		AlreadyConnected: result.AlreadyConnected,
		Target:           result.Target,
		KeyCount:         result.KeyCount,
		Locked:           result.Locked,
	}, nil
}

// Disconnect closes the connection to Signer
func (e *Core) Disconnect() {
	e.Connection.Disconnect(e.handleConnectionClosed(nil))
}

// IsConnected returns the current connection status
func (e *Core) IsConnected() bool {
	return e.Connection.IsConnected()
}

// GetConnectionTarget returns the current connection target
func (e *Core) GetConnectionTarget() string {
	return e.Connection.GetConnectionTarget()
}

// RequestEnrollmentWithContext asks a node to enroll this client's SSH key.
// The request uses its own short-lived SSH connection and leaves a live
// tunnel alone: the answer is normally "pending", and the caller decides
// whether to replace its session once the key is enrolled.
func (e *Core) RequestEnrollmentWithContext(ctx context.Context, host string, sshPort int, identityFile string, knownHostsPath string, label string, hostKeyApproval sshtunnel.HostKeyApprovalHandler, onEnrollmentStart func(string)) (connect.EnrollmentResult, error) {
	return e.Connection.RequestEnrollmentWithContext(ctx, host, sshPort, identityFile, knownHostsPath, label, hostKeyApproval, onEnrollmentStart)
}

func (e *Core) GetKeysWithContext(ctx context.Context) (*signerclient.KeysResult, error) {
	return e.Connection.GetKeysWithContext(ctx)
}

func (e *Core) GetKeyTypesWithContext(ctx context.Context) (*signerapi.KeyTypesResponse, error) {
	return e.Connection.GetKeyTypesWithContext(ctx)
}

func (e *Core) GetSignerStatusWithContext(ctx context.Context) (*signerapi.StatusResponse, error) {
	return e.Connection.GetSignerStatusWithContext(ctx)
}

func (e *Core) AdminGenerateWithContext(ctx context.Context, keyType string, params map[string]string) (*signerapi.AdminGenerateResponse, error) {
	return e.Connection.AdminGenerateWithContext(ctx, keyType, params)
}

func (e *Core) AdminDeleteKeyWithContext(ctx context.Context, address string) (*signerapi.AdminDeleteResponse, error) {
	return e.Connection.AdminDeleteKeyWithContext(ctx, address)
}

// RequestGroupPlanWithContext sends requests to /plan once every transaction
// they carry is for the active algod's network, and returns the answer only
// once it passes the check the presign-plan and cosigned flows make of
// theirs (validateGroupPlanAnswer). JS plan(), whose requests arrive as
// bytes, reaches /plan through here; the presign-plan flow checks its draft
// itself and calls the signer connection directly.
func (e *Core) RequestGroupPlanWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupPlanResponse, error) {
	txns, err := planRequestTransactions(requests)
	if err != nil {
		return nil, err
	}
	if err := e.checkActiveNetwork(ctx, txns); err != nil {
		return nil, err
	}
	response, err := e.Connection.RequestGroupPlanWithContext(ctx, requests)
	if err != nil {
		return nil, err
	}
	if err := validateGroupPlanAnswer(requests, txns, response); err != nil {
		return nil, fmt.Errorf("invalid group plan: %w", err)
	}
	return response, nil
}

// validateGroupPlanAnswer checks a /plan answer against the requests it
// answers, as the presign-plan flow checks its own: each planned transaction
// is decoded canonically, the group may differ from the transactions sent only
// as clientsign.ValidateGroupPlan allows (the report's counts, the group ID, a
// fee raise the report lists, canonical dummies appended), and the fee of a
// foreign position, which the signer does not sign, may not change at all. A
// group with a passthrough position may not change at all: the signer plans
// it as immutable (no fee raise anywhere, no dummies, no new group ID), since
// any change would void the signature the position carries. txns are the
// requests' transactions, a passthrough entry's being the one inside its
// signed bytes.
func validateGroupPlanAnswer(requests []signerapi.SignRequest, txns []types.Transaction, response *signerapi.GroupPlanResponse) error {
	if response == nil {
		return errors.New("signer returned no plan")
	}
	planned, err := clientsign.DecodePlannedGroup(response.Transactions)
	if err != nil {
		return err
	}
	foreign := make(map[int]string)
	passthrough := false
	for i, request := range requests {
		switch mode, _ := request.Mode(); mode {
		case signerapi.RequestModeForeign:
			foreign[i] = "foreign"
		case signerapi.RequestModePassthrough:
			passthrough = true
		}
	}
	if passthrough {
		if len(planned) != len(txns) {
			return fmt.Errorf("a group with a passthrough position is immutable, but the signer returned %d transaction(s) for its %d", len(planned), len(txns))
		}
		for i := range txns {
			if !bytes.Equal(msgpack.Encode(planned[i]), msgpack.Encode(txns[i])) {
				return fmt.Errorf("a group with a passthrough position is immutable, but the signer changed the transaction at index %d", i)
			}
		}
	}
	if err := clientsign.ValidateGroupPlan(txns, planned, response.Mutations); err != nil {
		return err
	}
	return clientsign.ValidateUnsignedFees(txns, planned, foreign)
}

func (e *Core) RequestGroupSignWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupSignResponse, error) {
	return e.Connection.RequestGroupSignWithContext(ctx, requests)
}

func (e *Core) handleConnectionClosed(onDisconnect func()) func() {
	return func() {
		e.resetSignerStatusRevision()
		e.resetSignerCache(false)
		if onDisconnect != nil {
			onDisconnect()
		}
	}
}
