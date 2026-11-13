// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"errors"
	"fmt"
	"testing"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/signing"
)

// A submission failure thrown by throwSubmitError reads as the string the
// submitting functions threw before it: uncaught, and concatenated by a
// script that caught it. It is an object now (typeof), and it carries the Go
// error, whose submission outcome the host reads.
func TestThrowSubmitErrorKeepsTheThrownText(t *testing.T) {
	_, vm, api := newTestAPI(t)
	cause := &signing.SubmissionError{TxIDs: []string{"A", "B"}, State: signing.SubmissionSubmitted, Err: errors.New("confirmation failed: timed out")}
	if err := vm.Set("failNew", func(goja.FunctionCall) goja.Value {
		api.throwSubmitError(fmt.Errorf("send() error submitting transaction: %w", cause))
		return goja.Undefined()
	}); err != nil {
		t.Fatal(err)
	}
	if err := vm.Set("failOld", func(goja.FunctionCall) goja.Value {
		panic(vm.ToValue(fmt.Sprintf("send() error submitting transaction: %v", cause)))
	}); err != nil {
		t.Fatal(err)
	}
	const want = "send() error submitting transaction: confirmation failed: timed out"

	for _, fn := range []string{"failNew", "failOld"} {
		_, err := vm.RunString(fn + "()")
		var exception *goja.Exception
		if !errors.As(err, &exception) || exception.Value().String() != want {
			t.Fatalf("%s() uncaught = %v, want %q", fn, err, want)
		}
		caught, err := vm.RunString(`try { ` + fn + `() } catch (e) { "failed: " + e }`)
		if err != nil || caught.String() != "failed: "+want {
			t.Fatalf("%s() caught = %v (%v), want %q", fn, caught, err, "failed: "+want)
		}
	}

	_, err := vm.RunString("failNew()")
	var exception *goja.Exception
	var failure *signing.SubmissionError
	if !errors.As(err, &exception) || !errors.As(exception.Unwrap(), &failure) || failure != cause {
		t.Fatalf("uncaught error %v does not carry the submission outcome", err)
	}
	kind, err := vm.RunString(`try { failNew() } catch (e) { typeof e + " " + e.message }`)
	if err != nil || kind.String() != "object "+want {
		t.Fatalf("caught = %v (%v), want an Error object with the message", kind, err)
	}
}
