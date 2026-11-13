// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dop251/goja"

	"github.com/aplane-algo/aplane/internal/signing"
)

// A submission failure thrown by throwSubmitError reads as the string the
// submitting functions threw before it: uncaught, and concatenated by a
// script that caught it. It is an object now (typeof).
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

	kind, err := vm.RunString(`try { failNew() } catch (e) { typeof e + " " + e.message }`)
	if err != nil || kind.String() != "object "+want {
		t.Fatalf("caught = %v (%v), want an Error object with the message", kind, err)
	}
}

// The thrown Error names the failed submission for a script that catches it:
// txids, every ID in order, and submission, its state when there is one.
// Several submissions (a sweep whose items failed) give every ID and no
// single state; a failure with no submission gives neither.
func TestThrowSubmitErrorNamesTheSubmission(t *testing.T) {
	_, vm, api := newTestAPI(t)
	var next error
	if err := vm.Set("fail", func(goja.FunctionCall) goja.Value {
		api.throwSubmitError(next)
		return goja.Undefined()
	}); err != nil {
		t.Fatal(err)
	}
	read := `try { fail() } catch (e) { JSON.stringify([e.txids, e.submission === undefined ? null : e.submission]) }`
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"one", fmt.Errorf("send() error: %w", &signing.SubmissionError{TxIDs: []string{"A", "B"}, State: signing.SubmissionUnknown, Err: errors.New("EOF")}),
			`[["A","B"],"unknown"]`},
		{"several", fmt.Errorf("sweep() error: %w", errors.Join(
			&signing.SubmissionError{TxIDs: []string{"A"}, State: signing.SubmissionSubmitted, Err: errors.New("x")},
			&signing.SubmissionError{TxIDs: []string{"C"}, State: signing.SubmissionRejected, Err: errors.New("y")})),
			`[["A","C"],null]`},
		{"none", errors.New("plugin() error: refused"), `[null,null]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next = tc.err
			got, err := vm.RunString(read)
			if err != nil || got.String() != tc.want {
				t.Fatalf("caught = %v (%v), want %s", got, err, tc.want)
			}
		})
	}
}

// Under a recording context every thrown submission failure is recorded, in
// order, whether the script catches it or not; without one nothing is.
func TestThrowSubmitErrorRecordsTheRunsSubmissions(t *testing.T) {
	_, vm, api := newTestAPI(t)
	n := 0
	if err := vm.Set("fail", func(goja.FunctionCall) goja.Value {
		n++
		api.throwSubmitError(&signing.SubmissionError{TxIDs: []string{fmt.Sprint("T", n)}, State: signing.SubmissionUnknown, Err: errors.New("EOF")})
		return goja.Undefined()
	}); err != nil {
		t.Fatal(err)
	}
	ctx, recorded := RecordSubmissions(context.Background())
	restore := api.SetContext(ctx)
	if _, err := vm.RunString(`try { fail() } catch (e) {} ; fail()`); err == nil {
		t.Fatal("the second failure was not thrown")
	}
	restore()
	got := recorded()
	if len(got) != 2 || got[0].TxIDs[0] != "T1" || got[1].TxIDs[0] != "T2" || got[0].State != "unknown" {
		t.Fatalf("recorded = %+v, want T1 (caught) and T2 (uncaught)", got)
	}
	if _, err := vm.RunString(`try { fail() } catch (e) {}`); err != nil {
		t.Fatal(err)
	}
	if again := recorded(); len(again) != 2 {
		t.Fatalf("a run without the recorder recorded into it: %+v", again)
	}
}
