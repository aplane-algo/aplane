// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRunLifecycleStopsServicesInReverseOrderAndDestroysRuntime(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	ir := productruntime.New(productruntime.Config{

		KeyStore:      keystore.NewAtomicFileKeyStoreForPaths(storepaths.NewPaths(root)),
		KeyPaths:      storepaths.NewPaths(root),
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()
	ir.SnapshotKeySession().InitializeSession()

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

	RunLifecycle(ctx, plan)

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
	closed           bool
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

	root := t.TempDir()
	ir := productruntime.New(productruntime.Config{

		KeyStore:      keystore.NewAtomicFileKeyStoreForPaths(storepaths.NewPaths(root)),
		KeyPaths:      storepaths.NewPaths(root),
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()
	ir.SnapshotKeySession().InitializeSession()

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
	if stopped, incompleteReason, closed := audit.snapshot(); stopped || incompleteReason == "" || closed {
		t.Fatalf("audit teardown = stopped %v incomplete %q closed %v, want incomplete record and open logger", stopped, incompleteReason, closed)
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

	root := t.TempDir()
	ir := productruntime.New(productruntime.Config{

		KeyStore:      keystore.NewAtomicFileKeyStoreForPaths(storepaths.NewPaths(root)),
		KeyPaths:      storepaths.NewPaths(root),
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()
	ir.SnapshotKeySession().InitializeSession()
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
