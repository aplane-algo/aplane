// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package scripting

import (
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/engine"
)

type scriptingPluginExecutor struct{}

func (scriptingPluginExecutor) ExecutePlugin(name string, args []string) (bool, string, interface{}, interface{}, error) {
	return true, name + ":" + strings.Join(args, ","), map[string]interface{}{"count": len(args)}, map[string]interface{}{"title": name}, nil
}

func newRunnerForTest(t *testing.T) *GojaRunner {
	t.Helper()

	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return NewGojaRunner(eng)
}

func TestGojaRunnerRunValuesAndEmptyResults(t *testing.T) {
	runner := newRunnerForTest(t)

	result, err := runner.Run("1 + 2")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.IsEmpty || result.Value != int64(3) {
		t.Fatalf("Run(1+2) = %#v, want value 3", result)
	}

	result, err = runner.Run("({answer: 42})")
	if err != nil {
		t.Fatalf("Run(object) error = %v", err)
	}
	obj, ok := result.Value.(map[string]interface{})
	if !ok || obj["answer"] != int64(42) {
		t.Fatalf("Run(object) = %#v, want exported map", result.Value)
	}

	for _, code := range []string{"undefined", "null"} {
		t.Run(code, func(t *testing.T) {
			got, err := runner.Run(code)
			if err != nil {
				t.Fatalf("Run(%s) error = %v", code, err)
			}
			if !got.IsEmpty {
				t.Fatalf("Run(%s) = %#v, want empty result", code, got)
			}
		})
	}
}

func TestGojaRunnerWrapsExceptionsAndSupportsOutputAndPlugins(t *testing.T) {
	runner := newRunnerForTest(t)

	var output []string
	runner.SetOutput(func(msg string) {
		output = append(output, msg)
	})
	runner.SetPluginExecutor(scriptingPluginExecutor{})

	result, err := runner.Run(`print("hi"); plugin("echo", "a", "b")`)
	if err != nil {
		t.Fatalf("Run(plugin) error = %v", err)
	}
	if len(output) != 1 || output[0] != "hi" {
		t.Fatalf("output = %#v, want print output", output)
	}
	obj, ok := result.Value.(map[string]interface{})
	if !ok || obj["success"] != true || obj["message"] != "echo:a,b" {
		t.Fatalf("plugin result = %#v, want success payload", result.Value)
	}
	if presentation, ok := obj["presentation"].(map[string]interface{}); !ok || presentation["title"] != "echo" {
		t.Fatalf("plugin presentation = %#v, want title echo", obj["presentation"])
	}

	_, err = runner.Run(`throw new Error("boom")`)
	if err == nil {
		t.Fatal("expected JS exception")
	}
	scriptErr, ok := err.(*RunnerError)
	if !ok {
		t.Fatalf("error type = %T, want *RunnerError", err)
	}
	if !strings.Contains(scriptErr.Error(), "boom") {
		t.Fatalf("error = %q, want boom", scriptErr.Error())
	}
}

func TestGojaRunnerSetOutputDoesNotHoldLockDuringStartupWarning(t *testing.T) {
	runner := newRunnerForTest(t)
	runner.startupWarning = "warning"

	done := make(chan struct{})
	go func() {
		runner.SetOutput(func(string) {
			runner.SetOutput(nil)
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SetOutput held runner lock while invoking startup warning callback")
	}
}

func TestGojaRunnerEmitStartupWarningDoesNotHoldLockDuringCallback(t *testing.T) {
	runner := newRunnerForTest(t)
	runner.startupWarning = "warning"
	runner.output = func(string) {
		runner.SetOutput(nil)
	}

	done := make(chan struct{})
	go func() {
		runner.emitStartupWarning()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("emitStartupWarning held runner lock while invoking callback")
	}
}

func TestGojaRunnerMixedOutputDoesNotBleedAcrossRuns(t *testing.T) {
	runner := newRunnerForTest(t)

	var output []string
	runner.SetOutput(func(msg string) {
		output = append(output, msg)
	})

	first, err := runner.Run(`print("first"); ({step: 1})`)
	if err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	if len(output) != 1 || output[0] != "first" {
		t.Fatalf("first output = %#v, want [first]", output)
	}
	firstObj, ok := first.Value.(map[string]interface{})
	if !ok || firstObj["step"] != int64(1) {
		t.Fatalf("first result = %#v, want structured map", first.Value)
	}

	output = output[:0]

	second, err := runner.Run(`print("second"); ({step: 2})`)
	if err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if len(output) != 1 || output[0] != "second" {
		t.Fatalf("second output = %#v, want [second]", output)
	}
	secondObj, ok := second.Value.(map[string]interface{})
	if !ok || secondObj["step"] != int64(2) {
		t.Fatalf("second result = %#v, want structured map", second.Value)
	}
	if secondObj["step"] == firstObj["step"] {
		t.Fatalf("second result unexpectedly reused first result: %#v vs %#v", secondObj, firstObj)
	}
}

func TestGojaRunnerRecoversNativePanics(t *testing.T) {
	runner := newRunnerForTest(t)
	if err := runner.Runtime().Set("explode", func() {
		panic("boom")
	}); err != nil {
		t.Fatalf("Set(explode) error = %v", err)
	}

	_, err := runner.Run(`explode()`)
	if err == nil {
		t.Fatal("expected native panic to be recovered")
	}
	if !strings.Contains(err.Error(), "script panic: boom") {
		t.Fatalf("error = %q, want recovered panic message", err.Error())
	}
}

func TestGojaRunnerInterrupt(t *testing.T) {
	runner := newRunnerForTest(t)

	done := make(chan error, 1)
	go func() {
		_, err := runner.Run("for (;;) {}")
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	runner.Interrupt()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected interrupt error")
		}
		if !strings.Contains(err.Error(), "script interrupted") {
			t.Fatalf("interrupt error = %q, want interruption message", err.Error())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for interrupted script")
	}
}

func TestGojaRunnerRestoresModeStateBetweenRuns(t *testing.T) {
	runner := newRunnerForTest(t)

	_, err := runner.Run(`setWriteMode(true); setSimulate(true); setVerbose(true); ({write: writeMode(), simulate: simulate()})`)
	if err != nil {
		t.Fatalf("first Run() error = %v", err)
	}

	result, err := runner.Run(`({write: writeMode(), simulate: simulate()})`)
	if err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	obj := result.Value.(map[string]interface{})
	if obj["write"] != false || obj["simulate"] != false {
		t.Fatalf("mode state leaked across runs: %#v", obj)
	}
}

func TestGojaRunnerEmitsStartupWarningOnce(t *testing.T) {
	runner := newRunnerForTest(t)
	runner.startupWarning = "Warning: warmup failed"

	var output []string
	runner.SetOutput(func(msg string) {
		output = append(output, msg)
	})

	if len(output) != 1 || output[0] != "Warning: warmup failed" {
		t.Fatalf("startup warning output = %#v, want single warning", output)
	}

	_, err := runner.Run("1 + 1")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(output) != 1 {
		t.Fatalf("startup warning re-emitted: %#v", output)
	}
}
