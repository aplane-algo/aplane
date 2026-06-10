// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"testing"
)

func TestPrepareAppDeploy_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := eng.PrepareAppDeploy(context.Background(), AppDeployParams{
		From: "alice",
		Approval: AppProgramSource{
			Path: "approval.teal",
		},
		Clear: AppProgramSource{
			Path: "clear.teal",
		},
	})
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}
