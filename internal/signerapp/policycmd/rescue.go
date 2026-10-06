// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/signerapp/policyapply"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// AcquireSharedStoreLock takes the cooperative read lock for offline reads.
var AcquireSharedStoreLock = storelock.AcquireShared

// RescueRunner runs policy commands directly against a stopped daemon's
// store. Reads hold the shared store lock; apply and remove hold the
// exclusive lock and commit through the same rules as the daemon.
type RescueRunner struct{}

func (r RescueRunner) Run(ctx context.Context, command Command, streams Streams) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if command.Verb == VerbTemplate {
		return WriteTemplate(command, streams)
	}
	if err := RejectRetiredEnvironment(); err != nil {
		return err
	}
	if command.DataDir == "" {
		return fmt.Errorf("signer data directory is required for policy rescue")
	}
	streams = streams.normalized()

	var guard *OfflineMutation
	if command.mutates() {
		var err error
		if guard, err = AcquireOfflineMutation(command.DataDir); err != nil {
			return fmt.Errorf("refusing offline policy %s: %w", command.Verb, err)
		}
		defer guard.Close()
	} else {
		lock, err := AcquireSharedStoreLock(command.DataDir)
		if err != nil {
			return fmt.Errorf("acquire signer-store lock (stop store-mutating tools first): %w", err)
		}
		defer func() { _ = lock.Close() }()
	}

	passphrase, err := ReadPassphrase(streams.Stdin, streams.Stderr, command.readsStdin())
	if err != nil {
		return err
	}
	paths := storepaths.NewPaths(command.DataDir)
	_, kr, err := genstore.OpenStoreRootSelection(paths, passphrase)
	crypto.ZeroBytes(passphrase)
	if err != nil {
		return fmt.Errorf("unlock keystore: %w", err)
	}
	defer kr.Zero()

	backend, err := newOfflineBackend(command.DataDir, paths, kr)
	if err != nil {
		return err
	}
	if err := run(ctx, command, streams, backend); err != nil {
		return err
	}
	if backend.committed {
		if err := guard.Normalize(); err != nil {
			return fmt.Errorf("policy applied, but managed store ownership normalization failed: %w", err)
		}
	}
	return nil
}

// offlineBackend serves policy requests from the store itself.
type offlineBackend struct {
	env       policyapply.Env
	current   *policyruntime.NodePolicy
	committed bool
}

func newOfflineBackend(dataDir string, paths storepaths.Paths, kr *crypto.Keyring) (*offlineBackend, error) {
	cfg, err := LoadServerConfig(dataDir)
	if err != nil {
		return nil, fmt.Errorf("load signer config: %w", err)
	}
	active, err := genstore.ResolveStoreRootWithKeyring(paths, kr)
	if err != nil {
		return nil, err
	}
	role, err := noderole.LoadAndVerifyGenerationWithKeyring(paths, active, kr)
	if err != nil {
		return nil, fmt.Errorf("verify node role: %w", err)
	}
	b := &offlineBackend{env: policyapply.Env{
		Role: role.Role, DataDir: dataDir, Config: &cfg, KeyPaths: paths, Keyring: kr,
	}}
	return b, b.reload()
}

func (b *offlineBackend) reload() error {
	active, err := genstore.ResolveStoreRootWithKeyring(b.env.KeyPaths, b.env.Keyring)
	if err != nil {
		return err
	}
	if b.current, err = policyruntime.Load(b.env.Role, b.env.DataDir, b.env.Config, active, b.env.Keyring); err != nil {
		return fmt.Errorf("verify active policy: %w", err)
	}
	b.env.HeldKeys, err = policyapply.HeldCosignerKeysInGeneration(active)
	return err
}

func (b *offlineBackend) Get(context.Context) (adminproto.PolicyView, error) {
	return policyapply.View(b.current, b.env.HeldKeys, ""), nil
}

func (b *offlineBackend) Document(_ context.Context, key string) (adminproto.PolicyDocumentResult, error) {
	return policyapply.Document(b.current, key), nil
}

func (b *offlineBackend) Check(_ context.Context, req adminproto.CheckPolicyRequest) (adminproto.CheckPolicyResult, error) {
	return policyapply.Check(b.env, b.current, req), nil
}

func (b *offlineBackend) Apply(_ context.Context, req adminproto.ApplyPolicyRequest) (adminproto.ApplyPolicyResult, error) {
	outcome, err := policyapply.Commit(b.env, req)
	if err != nil {
		return adminproto.ApplyPolicyResult{
			Code: policyapply.Code(err, "policy_apply_failed"), Error: err.Error(),
			Errors: outcome.Problems, CommitUncertain: outcome.Uncertain,
		}, nil
	}
	if outcome.GenerationID != "" {
		b.committed = true
		if err := b.reload(); err != nil {
			return adminproto.ApplyPolicyResult{}, fmt.Errorf("policy applied as generation %s, but reloading it failed: %w", outcome.GenerationID, err)
		}
	}
	view := policyapply.View(b.current, b.env.HeldKeys, outcome.GenerationID)
	return adminproto.ApplyPolicyResult{Success: true, Policy: &view}, nil
}
