// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

func TestClassifySentryDiscoveryQueryErrorUsesWireCodeBeforeStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		code       string
		want       error
	}{
		{
			name:       "locked 403 is locked not auth",
			statusCode: http.StatusForbidden,
			code:       signerapi.ErrCodeLocked,
			want:       ErrSentryDiscoveryLocked,
		},
		{
			name:       "cache refresh 500 is unavailable",
			statusCode: http.StatusInternalServerError,
			code:       signerapi.ErrCodeCacheRefresh,
			want:       ErrSentryDiscoveryUnavailable,
		},
		{
			name:       "bad request 500 is config by code",
			statusCode: http.StatusInternalServerError,
			code:       signerapi.ErrCodeBadRequest,
			want:       ErrSentryDiscoveryConfig,
		},
		{
			name:       "old forbidden response falls back to auth",
			statusCode: http.StatusForbidden,
			want:       ErrSentryDiscoveryAuth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classifySentryDiscoveryQueryError(&signerclient.HTTPStatusError{
				StatusCode: tt.statusCode,
				Code:       tt.code,
				Message:    tt.name,
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("classifySentryDiscoveryQueryError() = %v, want %v", err, tt.want)
			}
		})
	}
}
