// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRunLifecycleStopsServicesInReverseOrderAndDestroysRuntime(t *testing.T) {
	t.Parallel()

	ir := newLifecycleTestRuntime(t)

	var mu sync.Mutex
	var events []string
	record := func(event string) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	plan := LifecyclePlan{
		ProductRuntime: ir,
		StartWatcher: func(*productruntime.Runtime) {
			record("watcher")
		},
		ShutdownTimeout: time.Second,
		Services: []LifecycleService{
			{
				Name: "svc1",
				Start: func(ctx context.Context, errs chan<- error) error {
					record("start:svc1")
					return nil
				},
				Stop: func(ctx context.Context) error {
					record("stop:svc1")
					return nil
				},
			},
			{
				Name: "svc2",
				Start: func(ctx context.Context, errs chan<- error) error {
					record("start:svc2")
					cancel()
					return nil
				},
				Stop: func(ctx context.Context) error {
					record("stop:svc2")
					return nil
				},
			},
		},
	}

	// A run ended by its context (a shutdown signal) is not a failure: the
	// signer exits 0.
	if err := RunLifecycle(ctx, plan); err != nil {
		t.Fatalf("RunLifecycle after cancel = %v, want nil", err)
	}

	want := []string{"watcher", "start:svc1", "start:svc2", "stop:svc2", "stop:svc1"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if _, err := ir.SnapshotKeySession().GetKey("missing"); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("runtime key session error = %v, want ErrStoreLocked after destroy", err)
	}
}

type lifecycleAuditRecorder struct {
	mu               sync.Mutex
	stopped          bool
	incompleteReason string
	flushed          bool
	closed           bool
}

func (r *lifecycleAuditRecorder) FlushSummaries() {
	r.mu.Lock()
	r.flushed = true
	r.mu.Unlock()
}

func (r *lifecycleAuditRecorder) summariesFlushed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushed || r.closed
}

func (r *lifecycleAuditRecorder) LogServerStopIncomplete(reason string) {
	r.mu.Lock()
	r.incompleteReason = reason
	r.mu.Unlock()
}

func (r *lifecycleAuditRecorder) LogServerStop() {
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
}

func (r *lifecycleAuditRecorder) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}

func (r *lifecycleAuditRecorder) snapshot() (stopped bool, incompleteReason string, closed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped, r.incompleteReason, r.closed
}

func TestShutdownLifecycleDoesNotDestroyRuntimeWhileHandlerOutlivesStopTimeout(t *testing.T) {
	t.Parallel()

	ir := newLifecycleTestRuntime(t)

	handlerRelease := make(chan struct{})
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		<-handlerRelease
	}()
	t.Cleanup(func() {
		select {
		case <-handlerDone:
		default:
			close(handlerRelease)
			<-handlerDone
		}
	})

	audit := &lifecycleAuditRecorder{}
	var warningsMu sync.Mutex
	var warnings []string
	shutdownLifecycle([]LifecycleService{{
		Name: "HTTP server",
		Stop: func(ctx context.Context) error {
			select {
			case <-handlerDone:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}}, LifecyclePlan{
		ProductRuntime:  ir,
		ShutdownTimeout: 10 * time.Millisecond,
		AuditLog:        audit,
		Warn: func(message string) {
			warningsMu.Lock()
			warnings = append(warnings, message)
			warningsMu.Unlock()
		},
	})

	if _, err := ir.SnapshotKeySession().GetKey("missing"); errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("runtime was destroyed after timed-out handler stop: %v", err)
	}
	if stopped, incompleteReason, closed := audit.snapshot(); stopped || incompleteReason == "" || closed || !audit.summariesFlushed() {
		t.Fatalf("audit teardown = stopped %v incomplete %q closed %v flushed %v, want incomplete record, flushed summaries and open logger", stopped, incompleteReason, closed, audit.summariesFlushed())
	}
	warningsMu.Lock()
	gotWarnings := append([]string(nil), warnings...)
	warningsMu.Unlock()
	if len(gotWarnings) != 2 {
		t.Fatalf("warnings = %v, want stop error and retained-state warning", gotWarnings)
	}
	close(handlerRelease)
	<-handlerDone
}

func TestShutdownLifecycleDestroysRuntimeAfterNonDeadlineStopError(t *testing.T) {
	t.Parallel()

	ir := newLifecycleTestRuntime(t)
	audit := &lifecycleAuditRecorder{}

	shutdownLifecycle([]LifecycleService{{
		Name: "SSH server",
		Stop: func(context.Context) error {
			return errors.New("listener close failed after handlers drained")
		},
	}}, LifecyclePlan{
		ProductRuntime: ir,
		AuditLog:       audit,
	})

	if _, err := ir.SnapshotKeySession().GetKey("missing"); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("runtime key session error = %v, want ErrStoreLocked after safe teardown", err)
	}
	if stopped, incompleteReason, closed := audit.snapshot(); stopped || incompleteReason == "" || !closed {
		t.Fatalf("audit teardown = stopped %v incomplete %q closed %v, want incomplete record and closed logger", stopped, incompleteReason, closed)
	}
}

func newLifecycleTestRuntime(t *testing.T) *productruntime.Runtime {
	t.Helper()
	root := t.TempDir()
	ir := productruntime.New(productruntime.Config{
		KeyStore: keystore.NewAtomicFileKeyStoreForPaths(storepaths.NewPaths(root)),
		KeyPaths: storepaths.NewPaths(root),
	})
	ir.SetUnlocked()
	ir.SnapshotKeySession().InitializeSession()
	return ir
}

// A service that cannot start (an HTTP port that cannot be bound) ends the
// run with its error, so the signer exits non-zero; the services already
// started are still stopped and the runtime destroyed. It once returned
// nothing and the signer exited 0.
func TestRunLifecycleReturnsAStartFailure(t *testing.T) {
	t.Parallel()

	ir := newLifecycleTestRuntime(t)
	bindErr := errors.New("address already in use")
	var mu sync.Mutex
	var events []string
	record := func(event string) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}
	err := RunLifecycle(context.Background(), LifecyclePlan{
		ProductRuntime:  ir,
		ShutdownTimeout: time.Second,
		Services: []LifecycleService{
			{
				Name:  "SSH server",
				Start: func(context.Context, chan<- error) error { record("start:ssh"); return nil },
				Stop:  func(context.Context) error { record("stop:ssh"); return nil },
			},
			{
				Name:  "HTTP server",
				Start: func(context.Context, chan<- error) error { return bindErr },
				Stop:  func(context.Context) error { record("stop:http"); return nil },
			},
		},
	})
	if !errors.Is(err, bindErr) {
		t.Fatalf("RunLifecycle = %v, want the start failure", err)
	}
	if want := []string{"start:ssh", "stop:ssh"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	if _, err := ir.SnapshotKeySession().GetKey("missing"); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("runtime key session error = %v, want ErrStoreLocked after destroy", err)
	}
}

// A service that stops serving with an error ends the run with that error,
// after the same shutdown, so the signer exits non-zero.
func TestRunLifecycleReturnsAServeFailure(t *testing.T) {
	t.Parallel()

	ir := newLifecycleTestRuntime(t)
	serveErr := errors.New("accept failed")
	stopped := false
	err := RunLifecycle(context.Background(), LifecyclePlan{
		ProductRuntime:  ir,
		ShutdownTimeout: time.Second,
		Services: []LifecycleService{{
			Name: "HTTP server",
			Start: func(_ context.Context, errs chan<- error) error {
				go func() { errs <- serveErr }()
				return nil
			},
			Stop: func(context.Context) error { stopped = true; return nil },
		}},
	})
	if !errors.Is(err, serveErr) {
		t.Fatalf("RunLifecycle = %v, want the serve failure", err)
	}
	if !stopped {
		t.Fatal("the failed service was not stopped")
	}
	if _, err := ir.SnapshotKeySession().GetKey("missing"); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("runtime key session error = %v, want ErrStoreLocked after destroy", err)
	}
}

// Shutdown waits for a key use in flight before it zeroes the keyring, and
// records a complete stop once the use has released its material.
func TestShutdownWaitsForAKeyUseBeforeZeroing(t *testing.T) {
	t.Parallel()

	ir := newLifecycleTestRuntime(t)
	useCtx, release := ir.KeyUseContext(context.Background())
	sessionLiveAtRelease := make(chan bool, 1)
	go func() {
		<-useCtx.Done()
		_, err := ir.SnapshotKeySession().GetKey("missing")
		sessionLiveAtRelease <- !errors.Is(err, keystore.ErrStoreLocked)
		release()
	}()
	audit := &lifecycleAuditRecorder{}
	shutdownLifecycle(nil, LifecyclePlan{ProductRuntime: ir, ShutdownTimeout: 5 * time.Second, AuditLog: audit})

	if !<-sessionLiveAtRelease {
		t.Fatal("the session was cleared before the key use released its material")
	}
	if _, err := ir.SnapshotKeySession().GetKey("missing"); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("runtime key session error = %v, want ErrStoreLocked after destroy", err)
	}
	if stopped, incompleteReason, closed := audit.snapshot(); !stopped || incompleteReason != "" || !closed {
		t.Fatalf("audit teardown = stopped %v incomplete %q closed %v, want SERVER_STOP and a closed logger", stopped, incompleteReason, closed)
	}
}

// A key use that outlives the shutdown deadline does not hold shutdown: the
// keyring is zeroed anyway, the stop is recorded as incomplete, and the audit
// log stays open for the user's own final record. Shutdown once waited for
// key users without a bound.
func TestShutdownBoundsItsWaitForAKeyUse(t *testing.T) {
	t.Parallel()

	ir := newLifecycleTestRuntime(t)
	_, release := ir.KeyUseContext(context.Background())
	t.Cleanup(release)
	audit := &lifecycleAuditRecorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		shutdownLifecycle(nil, LifecyclePlan{ProductRuntime: ir, ShutdownTimeout: 50 * time.Millisecond, AuditLog: audit})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown waited on a key use past its deadline")
	}

	if _, err := ir.SnapshotKeySession().GetKey("missing"); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("runtime key session error = %v, want ErrStoreLocked after destroy", err)
	}
	if stopped, incompleteReason, closed := audit.snapshot(); stopped || !strings.Contains(incompleteReason, "key use") || closed || !audit.summariesFlushed() {
		t.Fatalf("audit teardown = stopped %v incomplete %q closed %v flushed %v, want the key use recorded, summaries flushed and the logger open", stopped, incompleteReason, closed, audit.summariesFlushed())
	}
}

// Every Start context has ended by the time the first Stop runs, whatever
// ended the run, so background work tied to it does not run on through the
// other services' stops. It once ended only with the caller's context, which
// a start or serve failure leaves running.
func TestShutdownEndsTheStartContextsBeforeAnyStop(t *testing.T) {
	t.Parallel()

	for _, failStart := range []bool{false, true} {
		var startCtx context.Context
		var endedAtStop []bool
		stop := func(context.Context) error {
			endedAtStop = append(endedAtStop, startCtx.Err() != nil)
			return nil
		}
		err := RunLifecycle(context.Background(), LifecyclePlan{
			ProductRuntime:  newLifecycleTestRuntime(t),
			ShutdownTimeout: time.Second,
			Services: []LifecycleService{
				{
					Name:  "worker",
					Start: func(ctx context.Context, _ chan<- error) error { startCtx = ctx; return nil },
					Stop:  stop,
				},
				{Name: "SSH server", Start: func(context.Context, chan<- error) error { return nil }, Stop: stop},
				{
					Name: "HTTP server",
					Start: func(_ context.Context, errs chan<- error) error {
						if failStart {
							return errors.New("address already in use")
						}
						errs <- errors.New("accept failed")
						return nil
					},
					Stop: stop,
				},
			},
		})
		if err == nil {
			t.Fatalf("failStart=%v: RunLifecycle = nil, want the failure", failStart)
		}
		if len(endedAtStop) == 0 || slices.Contains(endedAtStop, false) {
			t.Fatalf("failStart=%v: Start context ended at each stop = %v, want true at every one", failStart, endedAtStop)
		}
	}
}

// A stop reporting ErrStillRunning is recorded as incomplete and teardown
// goes on, even when its error also carries a context deadline, which on its
// own means a handler may still run and teardown is skipped. The final line
// says the shutdown was incomplete; it once said "shutdown complete" after
// any stop error.
func TestShutdownTearsDownPastAServiceStillRunning(t *testing.T) {
	t.Parallel()

	ir := newLifecycleTestRuntime(t)
	audit := &lifecycleAuditRecorder{}
	var mu sync.Mutex
	var infos []string
	shutdownLifecycle([]LifecycleService{{
		Name: "rotating stage table worker",
		Stop: func(ctx context.Context) error {
			return fmt.Errorf("%w at the shutdown deadline: %w", ErrStillRunning, context.DeadlineExceeded)
		},
	}}, LifecyclePlan{
		ProductRuntime: ir,
		AuditLog:       audit,
		Info: func(message string) {
			mu.Lock()
			infos = append(infos, message)
			mu.Unlock()
		},
	})

	if _, err := ir.SnapshotKeySession().GetKey("missing"); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("runtime key session error = %v, want ErrStoreLocked after teardown", err)
	}
	if stopped, incompleteReason, closed := audit.snapshot(); stopped || !strings.HasPrefix(incompleteReason, "rotating stage table worker: still running") || !closed {
		t.Fatalf("audit teardown = stopped %v incomplete %q closed %v, want the worker recorded and a closed logger", stopped, incompleteReason, closed)
	}
	mu.Lock()
	last := infos[len(infos)-1]
	mu.Unlock()
	if !strings.HasPrefix(last, "shutdown finished incomplete: rotating stage table worker") {
		t.Fatalf("final shutdown line = %q, want it to say the shutdown was incomplete", last)
	}
}
