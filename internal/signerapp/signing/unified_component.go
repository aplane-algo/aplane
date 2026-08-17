// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// SignComponentsWithContext dispatches one validated, discriminated component
// request without merging the authorization gates behind each target kind.
// Mixed kinds remain closed until the end-to-end mixed choreography is enabled.
func (s *Service) SignComponentsWithContext(ctx context.Context, identityID string, req signerapi.ComponentRequest, session *keystore.KeySession) (*signerapi.ComponentResponse, *ServiceError) {
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	switch req.TargetKind() {
	case signerapi.ComponentTargetKindUser, signerapi.ComponentTargetKindSentry:
		result, err := s.SignComponentWithContext(ctx, identityID, req.LegacySignRequest(), session)
		if err != nil {
			return nil, err
		}
		components := make([]signerapi.Component, 0, len(result.Signatures))
		for _, signature := range result.Signatures {
			components = append(components, signerapi.Component{
				TargetIndex: signature.TargetIndex, Kind: req.TargetKind(),
				Signature: signature.Signature, SignatureScheme: signature.SignatureScheme,
			})
		}
		return &signerapi.ComponentResponse{RequestID: result.RequestID, Components: components}, nil
	case signerapi.ComponentTargetKindBoundedBase:
		result, err := s.PrepareBoundedComponentWithContext(ctx, identityID, req.BoundedRequest(), session)
		if err != nil {
			return nil, err
		}
		components := make([]signerapi.Component, 0, len(result.Components))
		for _, component := range result.Components {
			components = append(components, signerapi.Component{
				TargetIndex: component.TargetIndex, Kind: signerapi.ComponentTargetKindBoundedBase,
				AuthAddress: component.BoundedAccount, BaseSignatures: component.BaseSignatures,
				RuntimeArgs: component.RuntimeArgs, AssemblyReceipt: component.AssemblyReceipt,
				SignatureScheme: component.SignatureScheme,
			})
		}
		return &signerapi.ComponentResponse{RequestID: result.RequestID, Components: components}, nil
	default:
		return nil, badRequest("unsupported component target kind")
	}
}
