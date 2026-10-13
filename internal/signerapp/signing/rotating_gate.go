// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// rejectRotatingKeyType refuses a rotating account on an ordinary signing
// path. Its authorizer changes on every spend and every signature must rekey
// to the next stage, so only the rotating flow may plan or sign for it. index
// is the zero-based slot.
func rejectRotatingKeyType(index int, keyType string) *ServiceError {
	if !rotatingkey.IsRotatingKeyType(keyType) {
		return nil
	}
	err := rotatingSigningRequired()
	err.Message = fmt.Sprintf("transaction %d: %s", index+1, err.Message)
	return err
}

// rejectRotatingComponentRequest refuses a component request that names a
// rotating account in any slot.
func (s *Service) rejectRotatingComponentRequest(req signerapi.ComponentRequest) *ServiceError {
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return internal("planner not configured")
	}
	keyTypes := s.Planner.Snapshot().KeyTypes
	for i, slot := range req.GroupSignRequest().Requests {
		if err := rejectRotatingKeyType(i, keyTypes[slot.AuthAddress]); err != nil {
			return err
		}
	}
	return nil
}
