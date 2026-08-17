// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// SignComponentsWithContext dispatches one validated, discriminated component
// request without merging the authorization gates behind each target kind.
// Mixed kinds remain closed until the end-to-end mixed choreography is enabled.
func (s *Service) SignComponentsWithContext(ctx context.Context, identityID string, req signerapi.ComponentRequest, session *keystore.KeySession) (*signerapi.ComponentResponse, *ServiceError) {
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	group, decodeErr := canonical.DecodeGroupHex(req.GroupBytesHex)
	if decodeErr != nil {
		return nil, badRequest(decodeErr.Error())
	}
	if err := validateFrozenComponentDummyPartition(req, makeTxnSlice(group)); err != nil {
		return nil, err
	}
	switch req.TargetKind() {
	case signerapi.ComponentTargetKindUser, signerapi.ComponentTargetKindSentry:
		planReq := componentPlanRequest{
			RequestID: req.RequestID, GroupBytesHex: req.GroupBytesHex,
			Requests: req.GroupSignRequest().Requests,
		}
		for _, target := range req.Targets {
			planReq.TargetIndices = append(planReq.TargetIndices, target.TargetIndex)
			if target.Kind == signerapi.ComponentTargetKindUser {
				planReq.Role = signerapi.ComponentSignRoleUser
				planReq.ComponentKey = target.AuthAddress
			} else {
				planReq.Role = signerapi.ComponentSignRoleSentry
				planReq.ComponentKey = target.ComponentKey
			}
		}
		result, err := s.signComponentWithContext(ctx, identityID, planReq, session)
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
		result, err := s.PrepareBoundedComponentWithContext(ctx, identityID, req, session)
		if err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, badRequest("unsupported component target kind")
	}
}
