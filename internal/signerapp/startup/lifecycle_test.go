// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestRunLifecycleStopsServicesInReverseOrderAndDestroysRuntimes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	reg := identity.NewRegistry()
	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      keystore.NewFileKeyStoreForPaths(storepaths.NewPaths(root), auth.DefaultIdentityID),
		KeyPaths:      storepaths.NewPaths(root),
		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()
	if err := reg.Register(ir); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	var mu sync.Mutex
	var events []string
	record := func(event string) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	plan := LifecyclePlan{
		Registry:       reg,
		ProductRuntime: ir,
		StartWatcher: func(*identity.Runtime) {
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
}
