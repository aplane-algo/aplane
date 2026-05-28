// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"testing"

	"github.com/aplane-algo/aplane/internal/shellrepl"
)

func TestOptOutRequestFromParamsPreservesFee(t *testing.T) {
	params, err := shellrepl.ParseOptoutCommand([]string{"usdc", "from", "alice", "to", "bob", "fee=3000", "nowait"})
	if err != nil {
		t.Fatalf("ParseOptoutCommand() error = %v", err)
	}

	req := optOutRequestFromParams(params)

	if req.Account != "alice" || req.AssetRef != "usdc" || req.CloseTo != "bob" {
		t.Fatalf("optOutRequestFromParams() = %+v, want alice/usdc/bob", req)
	}
	if req.Fee != 3000 || !req.UseFlatFee {
		t.Fatalf("fee fields = (%d, %v), want (3000, true)", req.Fee, req.UseFlatFee)
	}
	if req.Wait {
		t.Fatal("Wait = true, want false")
	}
}

func TestCloseRequestFromParamsPreservesFeeAndLsigArgs(t *testing.T) {
	params, err := shellrepl.ParseCloseCommand([]string{"alice", "to", "bob", "fee=4000", "nowait", "arg:preimage=text:secret"})
	if err != nil {
		t.Fatalf("ParseCloseCommand() error = %v", err)
	}

	req := closeRequestFromParams(params)

	if req.Account != "alice" || req.CloseTo != "bob" {
		t.Fatalf("closeRequestFromParams() = %+v, want alice/bob", req)
	}
	if req.Fee != 4000 || !req.UseFlatFee {
		t.Fatalf("fee fields = (%d, %v), want (4000, true)", req.Fee, req.UseFlatFee)
	}
	if req.Wait {
		t.Fatal("Wait = true, want false")
	}
	if got := req.LsigArgs["preimage"]; !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("LsigArgs[preimage] = %q, want secret", string(got))
	}
}
