// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// countingPluginExecutor counts the plugin commands it is asked to run.
type countingPluginExecutor struct{ calls int }

func (e *countingPluginExecutor) ExecutePlugin(string, []string) (bool, string, interface{}, interface{}, error) {
	e.calls++
	return true, "ran", nil, nil, nil
}

// A call the script makes after the cancellation, before the runner's
// interrupt reaches it, is not run and prints nothing: a loop that catches
// every error cannot fill the output with reports. Nothing interrupts the VM
// here, which stands for that moment.
func TestHostCallMadeAfterTheCancelIsNotRun(t *testing.T) {
	eng := newTempStoreEngine(t)
	vm := goja.New()
	var output []string
	api := NewAPI(eng, false, func(msg string) { output = append(output, msg) })
	if err := api.RegisterAll(vm); err != nil {
		t.Fatalf("RegisterAll() error = %v", err)
	}
	executor := &countingPluginExecutor{}
	api.SetPluginExecutor(executor)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	defer api.SetContext(ctx)()

	value, err := vm.RunString(`
		let last;
		for (let i = 0; i < 100; i++) {
			try { plugin("swap") } catch (e) { last = String(e) }
		}
		last`)
	if err != nil {
		t.Fatalf("RunString() error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatalf("plugin executor ran %d times after the cancel, want 0", executor.calls)
	}
	if len(output) != 0 {
		t.Fatalf("output = %q, want nothing", output)
	}
	if got, want := value.String(), "plugin() not run: the script was interrupted (context canceled)"; got != want {
		t.Fatalf("caught = %q, want %q", got, want)
	}
}

func TestReportedValueIsOneBoundedLine(t *testing.T) {
	vm := goja.New()
	accounts := make([]string, 300)
	for i := range accounts {
		accounts[i] = fmt.Sprintf("ACCOUNT%03dXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", i)
	}
	fn, err := vm.RunString("(function () {\n  return 1;\n})")
	if err != nil {
		t.Fatalf("RunString() error = %v", err)
	}

	tests := []struct {
		name  string
		value goja.Value
		want  string // prefix of the report
	}{
		{name: "short value in full", value: vm.ToValue(map[string]interface{}{"txid": "TXID1"}), want: `{"txid":"TXID1"}`},
		{name: "long array", value: vm.ToValue(accounts), want: `["ACCOUNT000`},
		{name: "multi-byte text", value: vm.ToValue(strings.Repeat("é", 400)), want: `"éé`},
		{name: "value with no JSON form", value: fn, want: `function () {\n  return 1;\n}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reportedValue(tt.value)
			if !strings.HasPrefix(got, tt.want) {
				t.Fatalf("reportedValue() = %q, want it to start with %q", got, tt.want)
			}
			if strings.ContainsAny(got, "\r\n") || !utf8.ValidString(got) {
				t.Fatalf("reportedValue() = %q, want one line of valid UTF-8", got)
			}
			shown, marker, truncated := strings.Cut(got, "... (truncated: ")
			if !truncated {
				if len(got) > reportedValueLimit {
					t.Fatalf("reportedValue() is %d bytes with no truncation marker", len(got))
				}
				return
			}
			if len(shown) > reportedValueLimit {
				t.Fatalf("reportedValue() shows %d bytes, want at most %d", len(shown), reportedValueLimit)
			}
			if want := fmt.Sprintf("%d of ", len(shown)); !strings.HasPrefix(marker, want) {
				t.Fatalf("truncation marker %q, want it to start with %q", marker, want)
			}
		})
	}
	full, err := json.Marshal(accounts)
	if err != nil {
		t.Fatal(err)
	}
	if got := reportedValue(vm.ToValue(accounts)); !strings.HasSuffix(got, fmt.Sprintf(" of %d bytes shown)", len(full))) {
		t.Fatalf("reportedValue() = %q, want the full size, %d bytes, in the marker", got, len(full))
	}
}
