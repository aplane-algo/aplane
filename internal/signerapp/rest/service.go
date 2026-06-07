// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rest

import (
	"context"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

type SigningService interface {
	SignGroupWithContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession) (*signersigning.SignGroupResult, *signersigning.ServiceError)
	SignGroupForSimulationWithContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession) (*signersigning.SignGroupResult, *signersigning.ServiceError)
	SignComponentWithContext(ctx context.Context, identityID string, req signerapi.ComponentSignRequest, session *keystore.KeySession) (*signersigning.ComponentSignResult, *signersigning.ServiceError)
	AssembleGuardedWithContext(ctx context.Context, identityID string, req signerapi.GuardedAssemblyRequest, session *keystore.KeySession) (*signersigning.GuardedAssemblyResult, *signersigning.ServiceError)
}

type SimulateSignedGroupFunc func(context.Context, []types.SignedTxn) ([]string, string, bool, *signersigning.ServiceError)

type Dependencies struct {
	NewSigningService   func(*identity.Runtime) SigningService
	PlanGroup           func(string, signerapi.GroupSignRequest) (*signersigning.PlanResult, *signersigning.ServiceError)
	EncodeTxnHex        func(types.Transaction) string
	SimulateSignedGroup SimulateSignedGroupFunc
	KeyAdmin            keyadmin.Service
	GenerateGenericLSig keyadmin.GenerateGenericLSigFunc
}

type Service struct {
	Deps Dependencies
}
