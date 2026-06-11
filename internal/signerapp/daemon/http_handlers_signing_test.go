// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapi"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

func TestSignCancelStateMapping(t *testing.T) {
	tests := []struct {
		name  string
		state signerapproval.SignRequestCancelState
		want  signerapi.SignCancelState
	}{
		{name: "canceled", state: signerapproval.SignRequestCancelStateCanceled, want: signerapi.SignCancelStateCanceled},
		{name: "not found", state: signerapproval.SignRequestCancelStateNotFound, want: signerapi.SignCancelStateNotFound},
		{name: "unknown defaults to not found", state: "unknown", want: signerapi.SignCancelStateNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signCancelState(tt.state); got != tt.want {
				t.Fatalf("signCancelState(%q) = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}
