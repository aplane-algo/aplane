// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package scripting

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
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

// syncOutput collects print output from the runner, which writes it from the
// script's goroutine.
type syncOutput struct {
	mu    sync.Mutex
	lines []string
}

func (o *syncOutput) write(msg string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lines = append(o.lines, msg)
}

func (o *syncOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return strings.Join(o.lines, "\n")
}

// runAsync starts code under ctx and returns a channel with the run's error.
func runAsync(runner *GojaRunner, ctx context.Context, code string) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := runner.RunWithContext(ctx, code)
		done <- err
	}()
	return done
}

func waitForRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the script to stop")
		return nil
	}
}

func requireCancelled(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "script interrupted") {
		t.Fatalf("run error = %v, want script interrupted wrapping context.Canceled", err)
	}
}

// requireRunsNormally checks that a later run is not hit by an interrupt
// left over from an earlier one.
func requireRunsNormally(t *testing.T, runner *GojaRunner) {
	t.Helper()
	result, err := runner.RunWithContext(context.Background(), "let n = 0; for (let i = 0; i < 100000; i++) { n++ } n")
	if err != nil {
		t.Fatalf("next run error = %v", err)
	}
	if result.Value != int64(100000) {
		t.Fatalf("next run = %#v, want 100000", result.Value)
	}
}

func TestGojaRunnerCancelInterruptsAnEndlessLoop(t *testing.T) {
	runner := newRunnerForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(runner, ctx, "while (true) {}")

	time.Sleep(20 * time.Millisecond)
	cancel()

	requireCancelled(t, waitForRun(t, done))
	requireRunsNormally(t, runner)
}

func TestGojaRunnerRefusesAnAlreadyCancelledContext(t *testing.T) {
	runner := newRunnerForTest(t)
	var output syncOutput
	runner.SetOutput(output.write)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := runner.RunWithContext(ctx, `print("ran")`)
	requireCancelled(t, err)
	if got := output.String(); got != "" {
		t.Fatalf("output = %q, want nothing run", got)
	}
	requireRunsNormally(t, runner)
}

func TestGojaRunnerCancelAfterCompletionIsANoOp(t *testing.T) {
	runner := newRunnerForTest(t)
	ctx, cancel := context.WithCancel(context.Background())

	result, err := runner.RunWithContext(ctx, "1 + 2")
	if err != nil || result.Value != int64(3) {
		t.Fatalf("run = %#v, %v; want 3", result, err)
	}
	cancel()

	requireRunsNormally(t, runner)
}

func TestGojaRunnerDiscardsAnInterruptBetweenRuns(t *testing.T) {
	runner := newRunnerForTest(t)
	runner.Interrupt()
	requireRunsNormally(t, runner)
}

// Every run's watcher exits when the run ends, cancelled or not.
func TestGojaRunnerLeavesNoWatcherBehind(t *testing.T) {
	runner := newRunnerForTest(t)
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		if _, err := runner.RunWithContext(ctx, "1"); err != nil {
			t.Fatalf("run %d error = %v", i, err)
		}
		cancel()
	}
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := runAsync(runner, ctx, "while (true) {}")
		time.Sleep(5 * time.Millisecond)
		cancel()
		requireCancelled(t, waitForRun(t, done))
	}
	// Allow the last runAsync goroutine a moment to return after its send.
	after := runtime.NumGoroutine()
	for deadline := time.Now().Add(time.Second); after > before+1 && time.Now().Before(deadline); after = runtime.NumGoroutine() {
		time.Sleep(10 * time.Millisecond)
	}
	if after > before+1 {
		t.Fatalf("goroutines = %d after 55 runs, %d before; a watcher was left running", after, before)
	}
}

// blockingPluginExecutor stands in for a host call that has submitted a
// transaction and is still finishing when the script is cancelled: it
// returns only when the test releases it.
type blockingPluginExecutor struct {
	started chan struct{}
	release chan struct{}
	err     error
}

func newBlockingPluginExecutor(err error) *blockingPluginExecutor {
	return &blockingPluginExecutor{started: make(chan struct{}), release: make(chan struct{}), err: err}
}

func (e *blockingPluginExecutor) ExecutePlugin(string, []string) (bool, string, interface{}, interface{}, error) {
	close(e.started)
	<-e.release
	if e.err != nil {
		return false, "", nil, nil, e.err
	}
	return true, "swapped", map[string]interface{}{"txids": []string{"TXID1"}}, nil, nil
}

func TestGojaRunnerCancelDuringAHostCallKeepsWhatItReturned(t *testing.T) {
	runner := newRunnerForTest(t)
	var output syncOutput
	runner.SetOutput(output.write)
	executor := newBlockingPluginExecutor(nil)
	runner.SetPluginExecutor(executor)
	ctx, cancel := context.WithCancel(context.Background())

	done := runAsync(runner, ctx, `const r = plugin("swap"); while (true) {}`)
	<-executor.started
	cancel()
	// The host call is not cut short: it finishes after the cancellation.
	close(executor.release)

	requireCancelled(t, waitForRun(t, done))
	want := `plugin() ended after the script was interrupted, returning: {"data":{"txids":["TXID1"]},"message":"swapped","success":true}`
	if got := output.String(); !strings.Contains(got, want) {
		t.Fatalf("output = %q, want %q", got, want)
	}
	requireRunsNormally(t, runner)
}

// However the run ends once its context is cancelled, the caller can tell it
// was cancelled (apconsole prints "Interrupted" by errors.Is), and an error of
// the script's own that ended it keeps its text.
func TestGojaRunnerCancelDuringAHostCallKeepsTheErrorItThrew(t *testing.T) {
	hostErr := "plugin() error: step 2 failed after step 1 submitted TXID1"
	for _, tt := range []struct {
		name string
		code string
		// wantScriptErr: the host call's error, not the interrupt, ends the run.
		wantScriptErr bool
	}{
		// The script would have caught the error, but the interrupt, or
		// the next host call refusing to run, stops it first.
		{name: "caught", code: `try { plugin("swap") } catch (e) { print("caught " + e) } while (true) {}`},
		// The error ends the run itself, before the VM sees the interrupt,
		// which goja then leaves set; the next run must not inherit it.
		{name: "uncaught", code: `plugin("swap")`, wantScriptErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runner := newRunnerForTest(t)
			var output syncOutput
			runner.SetOutput(output.write)
			executor := newBlockingPluginExecutor(errors.New("step 2 failed after step 1 submitted TXID1"))
			runner.SetPluginExecutor(executor)
			ctx, cancel := context.WithCancel(context.Background())

			done := runAsync(runner, ctx, tt.code)
			<-executor.started
			cancel()
			close(executor.release)

			err := waitForRun(t, done)
			requireCancelled(t, err)
			if tt.wantScriptErr {
				var runnerErr *RunnerError
				if !errors.As(err, &runnerErr) || !strings.Contains(err.Error(), "the script ended with: "+hostErr) {
					t.Fatalf("run error = %v, want it to keep the script's error %q", err, hostErr)
				}
			}
			want := "plugin() ended after the script was interrupted, failing with: " + hostErr
			if got := output.String(); !strings.Contains(got, want) || strings.Contains(got, "caught") {
				t.Fatalf("output = %q, want %q and nothing from the catch block", got, want)
			}
			requireRunsNormally(t, runner)
		})
	}
}

// A script that runs to its end once its context is cancelled, because the
// host call in flight returned before the interrupt reached it, still reports
// the cancellation rather than a result.
func TestGojaRunnerRunThatFinishesAfterTheCancelReportsIt(t *testing.T) {
	runner := newRunnerForTest(t)
	executor := newBlockingPluginExecutor(nil)
	runner.SetPluginExecutor(executor)
	ctx, cancel := context.WithCancel(context.Background())

	done := runAsync(runner, ctx, `plugin("swap")`)
	<-executor.started
	cancel()
	close(executor.release)

	requireCancelled(t, waitForRun(t, done))
	requireRunsNormally(t, runner)
}

// A host call that ends before the cancellation reached the script on its
// own, so nothing about it is printed again.
func TestGojaRunnerDoesNotReportHostCallsThatEndedBeforeTheCancel(t *testing.T) {
	runner := newRunnerForTest(t)
	var output syncOutput
	runner.SetOutput(output.write)
	runner.SetPluginExecutor(scriptingPluginExecutor{})
	ctx, cancel := context.WithCancel(context.Background())

	done := runAsync(runner, ctx, `plugin("echo", "a"); while (true) {}`)
	time.Sleep(20 * time.Millisecond)
	cancel()

	requireCancelled(t, waitForRun(t, done))
	if got := output.String(); got != "" {
		t.Fatalf("output = %q, want nothing reported", got)
	}
}
