// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"strings"
	"testing"
)

func TestCmdRotateRejectsBadUsage(t *testing.T) {
	r := &REPLState{}
	for _, args := range [][]string{
		{},
		{"vault", "later"},
		{"vault", "nowait", "extra"},
		{"status", "vault", "extra"},
		{"exit", "vault", "to", "bob"},
		{"recover"},
		{"recover", "vault", "--stage"},
		{"recover", "vault", "--depth", "3"},
		{"recover", "vault", "cancel", "now"},
	} {
		if _, err := r.cmdRotate(args, nil); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("args %v: err = %v, want usage error", args, err)
		}
	}
	if _, err := r.cmdRotate([]string{"recover", "vault", "--stage", "ten"}, nil); err == nil || !strings.Contains(err.Error(), "not a non-negative integer") {
		t.Fatalf("bad number: %v", err)
	}
	if _, err := r.cmdRotate([]string{"recover", "vault", "--window", "3"}, nil); err == nil || !strings.Contains(err.Error(), "--window needs --stage") {
		t.Fatalf("window without stage: %v", err)
	}
}

func TestParseRotateRecover(t *testing.T) {
	req, err := parseRotateRecover([]string{"vault", "--stage", "10000", "--window", "8", "--max-stages", "500", "--timeout", "90"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Account != "vault" || req.Cancel || req.Stage == nil || *req.Stage != 10000 || req.Window != 8 || req.MaxStages != 500 || req.TimeoutSeconds != 90 {
		t.Fatalf("parsed = %+v", req)
	}
	req, err = parseRotateRecover([]string{"vault", "cancel"})
	if err != nil || !req.Cancel || req.Account != "vault" {
		t.Fatalf("cancel parsed = %+v, %v", req, err)
	}
	req, err = parseRotateRecover([]string{"vault"})
	if err != nil || req.Cancel || req.Stage != nil || req.MaxStages != 0 {
		t.Fatalf("bare recover parsed = %+v, %v", req, err)
	}
}
