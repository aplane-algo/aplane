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
	PrepareBoundedAdminWithContext(ctx context.Context, identityID string, req signerapi.BoundedAdminRequest, session *keystore.KeySession) (*signersigning.BoundedAdminResult, *signersigning.ServiceError)
	SignComponentsWithContext(ctx context.Context, identityID string, req signerapi.ComponentRequest, session *keystore.KeySession) (*signerapi.ComponentResponse, *signersigning.ServiceError)
	AssembleWithContext(ctx context.Context, identityID string, req signerapi.AssemblyRequest, session *keystore.KeySession) (*signersigning.AssemblyResult, *signersigning.ServiceError)
}

type Dependencies struct {
	NewSigningService   func(*identity.Runtime) SigningService
	PlanGroup           func(string, signerapi.GroupSignRequest) (*signersigning.PlanResult, *signersigning.ServiceError)
	EncodeTxnHex        func(types.Transaction) string
	KeyAdmin            keyadmin.Service
	GenerateGenericLSig keyadmin.GenerateGenericLSigFunc
}

type Service struct {
	Deps Dependencies
}
