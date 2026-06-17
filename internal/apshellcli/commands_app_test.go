// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"encoding/hex"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appinput"
)

func TestParseRawAppCallArgs(t *testing.T) {
	params, err := parseRawAppCallArgs([]string{
		"raw", "123", "from", "alice",
		"arg-raw=hex:8296da2e",
		"arg-raw=text:hello",
		"--pay", "100000",
		"account=bob",
		"app=456",
		"asset=usdc",
		"box=456:hex:636f6e666967",
		"oncomp=noop",
		"note=test",
		"fee=2000",
		"nowait",
		"arg:preimage=text:secret",
	})
	if err != nil {
		t.Fatalf("parseRawAppCallArgs() error = %v", err)
	}

	if params.AppID != 123 || params.From != "alice" {
		t.Fatalf("unexpected core params: %+v", params)
	}
	if params.Wait {
		t.Fatal("expected nowait to disable waiting")
	}
	if len(params.AppArgs) != 2 {
		t.Fatalf("expected 2 app args, got %d", len(params.AppArgs))
	}
	if params.PayAmount != 100000 {
		t.Fatalf("pay amount = %d, want 100000", params.PayAmount)
	}
	if got := hex.EncodeToString(params.AppArgs[0]); got != "8296da2e" {
		t.Fatalf("selector arg = %s, want 8296da2e", got)
	}
	if string(params.AppArgs[1]) != "hello" {
		t.Fatalf("second arg = %q, want hello", string(params.AppArgs[1]))
	}
	if len(params.Accounts) != 1 || params.Accounts[0] != "bob" {
		t.Fatalf("accounts = %+v, want [bob]", params.Accounts)
	}
	if len(params.ForeignApps) != 1 || params.ForeignApps[0] != 456 {
		t.Fatalf("foreign apps = %+v, want [456]", params.ForeignApps)
	}
	if len(params.AssetRefs) != 1 || params.AssetRefs[0] != "usdc" {
		t.Fatalf("asset refs = %+v, want [usdc]", params.AssetRefs)
	}
	if len(params.Boxes) != 1 || params.Boxes[0].AppID != 456 || string(params.Boxes[0].Name) != "config" {
		t.Fatalf("boxes = %+v, want box on app 456/config", params.Boxes)
	}
	if params.OnCompletion != types.NoOpOC || params.Note != "test" || params.Fee != 2000 || !params.UseFlatFee {
		t.Fatalf("unexpected optional params: %+v", params)
	}
}

func TestParseRawAppCallArgs_WithLsigArgsAndImplicitProgramDetection(t *testing.T) {
	params, err := parseRawAppCallArgs([]string{
		"raw", "123", "from", "alice",
		"oncomp=update",
		"approval=/tmp/approval.teal",
		"clear=/tmp/clear.bin",
		"arg:preimage=hello",
		"arg:hash=0x0102",
	})
	if err != nil {
		t.Fatalf("parseRawAppCallArgs() error = %v", err)
	}

	if params.OnCompletion != types.UpdateApplicationOC {
		t.Fatalf("OnCompletion = %v, want update", params.OnCompletion)
	}
	if params.ApprovalCompiled {
		t.Fatalf("ApprovalCompiled = true, want false for .teal")
	}
	if !params.ClearCompiled {
		t.Fatalf("ClearCompiled = false, want true for .bin")
	}
	if string(params.LsigArgs["preimage"]) != "hello" {
		t.Fatalf("LsigArgs[preimage] = %q, want hello", string(params.LsigArgs["preimage"]))
	}
	if got := hex.EncodeToString(params.LsigArgs["hash"]); got != "0102" {
		t.Fatalf("LsigArgs[hash] = %s, want 0102", got)
	}
}

func TestParseBoxRef(t *testing.T) {
	ref, err := parseBoxRef("456:hex:636f6e666967", 123)
	if err != nil {
		t.Fatalf("parseBoxRef() error = %v", err)
	}
	if ref.AppID != 456 || string(ref.Name) != "config" {
		t.Fatalf("unexpected ref: %+v", ref)
	}

	ref, err = parseBoxRef("settings", 123)
	if err != nil {
		t.Fatalf("parseBoxRef() error = %v", err)
	}
	if ref.AppID != 123 || string(ref.Name) != "settings" {
		t.Fatalf("unexpected default-app ref: %+v", ref)
	}
}

func TestParseBoxRefRejectsEmptyName(t *testing.T) {
	_, err := parseBoxRef("", 123)
	if err == nil || err.Error() != "box name must be non-empty" {
		t.Fatalf("expected empty-box-name error, got %v", err)
	}
}

func TestParseOnCompletion(t *testing.T) {
	tests := map[string]types.OnCompletion{
		"noop":     types.NoOpOC,
		"optin":    types.OptInOC,
		"closeout": types.CloseOutOC,
		"clear":    types.ClearStateOC,
		"update":   types.UpdateApplicationOC,
		"delete":   types.DeleteApplicationOC,
	}

	for raw, want := range tests {
		got, err := appinput.ParseOnCompletion(raw)
		if err != nil {
			t.Fatalf("ParseOnCompletion(%q) error = %v", raw, err)
		}
		if got != want {
			t.Fatalf("ParseOnCompletion(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestParseMethodAppCallArgs(t *testing.T) {
	params, err := parseMethodAppCallArgs([]string{
		"123", "increment",
		"--abi", "/tmp/test.json",
		"from", "alice",
		"--arg", "11",
		"--pay", "100000",
		"account=bob",
		"app=456",
		"asset=usdc",
		"box=456:hex:636f6e666967",
		"oncomp=noop",
		"note=test",
		"fee=2000",
		"nowait",
		"arg:preimage=text:secret",
	})
	if err != nil {
		t.Fatalf("parseMethodAppCallArgs() error = %v", err)
	}

	if params.AppID != 123 || params.Method != "increment" || params.ABIPath != "/tmp/test.json" || params.From != "alice" {
		t.Fatalf("unexpected core params: %+v", params)
	}
	if len(params.ArgValues) != 1 || params.ArgValues[0] != "11" {
		t.Fatalf("arg values = %+v, want [11]", params.ArgValues)
	}
	if params.PayAmount != 100000 {
		t.Fatalf("pay amount = %d, want 100000", params.PayAmount)
	}
	if params.Wait {
		t.Fatal("expected nowait to disable waiting")
	}
	if len(params.Accounts) != 1 || params.Accounts[0] != "bob" {
		t.Fatalf("accounts = %+v, want [bob]", params.Accounts)
	}
	if len(params.ForeignApps) != 1 || params.ForeignApps[0] != 456 {
		t.Fatalf("foreign apps = %+v, want [456]", params.ForeignApps)
	}
	if len(params.AssetRefs) != 1 || params.AssetRefs[0] != "usdc" {
		t.Fatalf("asset refs = %+v, want [usdc]", params.AssetRefs)
	}
	if len(params.Boxes) != 1 || params.Boxes[0].AppID != 456 || string(params.Boxes[0].Name) != "config" {
		t.Fatalf("boxes = %+v, want box on app 456/config", params.Boxes)
	}
	if params.OnCompletion != types.NoOpOC || params.Note != "test" || params.Fee != 2000 || !params.UseFlatFee {
		t.Fatalf("unexpected optional params: %+v", params)
	}
}

func TestParseMethodAppCallArgs_WithLsigArgsAndUpdatePrograms(t *testing.T) {
	params, err := parseMethodAppCallArgs([]string{
		"123", "increment",
		"--abi", "/tmp/test.json",
		"from", "alice",
		"oncomp=update",
		"approval=/tmp/approval.teal",
		"clear=/tmp/clear.bin",
		"arg:preimage=hello",
		"arg:hash=0x0102",
	})
	if err != nil {
		t.Fatalf("parseMethodAppCallArgs() error = %v", err)
	}

	if params.OnCompletion != types.UpdateApplicationOC {
		t.Fatalf("OnCompletion = %v, want update", params.OnCompletion)
	}
	if params.ApprovalCompiled {
		t.Fatalf("ApprovalCompiled = true, want false for .teal")
	}
	if !params.ClearCompiled {
		t.Fatalf("ClearCompiled = false, want true for .bin")
	}
	if string(params.LsigArgs["preimage"]) != "hello" {
		t.Fatalf("LsigArgs[preimage] = %q, want hello", string(params.LsigArgs["preimage"]))
	}
	if got := hex.EncodeToString(params.LsigArgs["hash"]); got != "0102" {
		t.Fatalf("LsigArgs[hash] = %s, want 0102", got)
	}
}

func TestParseRawAppCallArgsUpdateRequiresPrograms(t *testing.T) {
	_, err := parseRawAppCallArgs([]string{
		"raw", "123", "from", "alice",
		"oncomp=update",
	})
	if err == nil || err.Error() != "app update requires approval=<path> or approval-bin=<path>" {
		t.Fatalf("expected missing-approval error, got %v", err)
	}
}

func TestParseRawAppCallArgsUpdatePrograms(t *testing.T) {
	params, err := parseRawAppCallArgs([]string{
		"raw", "123", "from", "alice",
		"oncomp=update",
		"approval-teal=/tmp/approval.teal",
		"clear-bin=/tmp/clear.bin",
	})
	if err != nil {
		t.Fatalf("parseRawAppCallArgs(update) error = %v", err)
	}
	if params.OnCompletion != types.UpdateApplicationOC {
		t.Fatalf("oncompletion = %v, want update", params.OnCompletion)
	}
	if params.ApprovalPath != "/tmp/approval.teal" || params.ApprovalCompiled {
		t.Fatalf("unexpected approval params: %+v", params)
	}
	if params.ClearPath != "/tmp/clear.bin" || !params.ClearCompiled {
		t.Fatalf("unexpected clear params: %+v", params)
	}
}

func TestParseMethodAppCallArgsRejectsProgramsWithoutUpdate(t *testing.T) {
	_, err := parseMethodAppCallArgs([]string{
		"123", "increment",
		"--abi", "/tmp/test.json",
		"from", "alice",
		"approval=/tmp/approval.teal",
	})
	if err == nil || err.Error() != "approval and clear programs are only valid with oncomp=update" {
		t.Fatalf("expected non-update program error, got %v", err)
	}
}

func TestParseMethodAppCallArgsUpdatePrograms(t *testing.T) {
	params, err := parseMethodAppCallArgs([]string{
		"123", "increment",
		"--abi", "/tmp/test.json",
		"from", "alice",
		"oncomp=update",
		"approval=/tmp/approval.teal",
		"clear=/tmp/clear.teal",
	})
	if err != nil {
		t.Fatalf("parseMethodAppCallArgs(update) error = %v", err)
	}
	if params.OnCompletion != types.UpdateApplicationOC {
		t.Fatalf("oncompletion = %v, want update", params.OnCompletion)
	}
	if params.ApprovalPath != "/tmp/approval.teal" || params.ApprovalCompiled {
		t.Fatalf("unexpected approval params: %+v", params)
	}
	if params.ClearPath != "/tmp/clear.teal" || params.ClearCompiled {
		t.Fatalf("unexpected clear params: %+v", params)
	}
}

func TestParseAppDeployArgs(t *testing.T) {
	params, err := parseAppDeployArgs([]string{
		"from", "alice",
		"approval-teal=/tmp/approval.teal",
		"clear-bin=/tmp/clear.bin",
		"global-uint=2",
		"global-bytes=3",
		"local-uint=1",
		"local-bytes=0",
		"extra-pages=1",
		"note=test",
		"fee=2000",
		"nowait",
		"arg:preimage=text:secret",
	})
	if err != nil {
		t.Fatalf("parseAppDeployArgs() error = %v", err)
	}

	if params.From != "alice" {
		t.Fatalf("from = %q, want alice", params.From)
	}
	if params.ApprovalPath != "/tmp/approval.teal" || params.ApprovalCompiled {
		t.Fatalf("unexpected approval params: %+v", params)
	}
	if params.ClearPath != "/tmp/clear.bin" || !params.ClearCompiled {
		t.Fatalf("unexpected clear params: %+v", params)
	}
	if params.GlobalUint != 2 || params.GlobalBytes != 3 || params.LocalUint != 1 || params.LocalBytes != 0 {
		t.Fatalf("unexpected schema params: %+v", params)
	}
	if params.ExtraPages != 1 {
		t.Fatalf("extra pages = %d, want 1", params.ExtraPages)
	}
	if params.Note != "test" || params.Fee != 2000 || !params.UseFlatFee {
		t.Fatalf("unexpected note/fee params: %+v", params)
	}
	if params.Wait {
		t.Fatal("expected nowait to disable waiting")
	}
	if got := string(params.LsigArgs["preimage"]); got != "secret" {
		t.Fatalf("LsigArgs[preimage] = %q, want secret", got)
	}
}

func TestParseAppDeployArgs_DetectProgramSources(t *testing.T) {
	params, err := parseAppDeployArgs([]string{
		"from", "alice",
		"approval=/tmp/approval.teal",
		"clear=/tmp/clear.bin",
		"global-uint=1",
		"global-bytes=0",
		"local-uint=0",
		"local-bytes=1",
	})
	if err != nil {
		t.Fatalf("parseAppDeployArgs() error = %v", err)
	}

	if params.ApprovalCompiled {
		t.Fatalf("ApprovalCompiled = true, want false for .teal")
	}
	if !params.ClearCompiled {
		t.Fatalf("ClearCompiled = false, want true for .bin")
	}
}
