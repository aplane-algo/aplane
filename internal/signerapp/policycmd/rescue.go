// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"fmt"
	"github.com/aplane-algo/aplane/internal/asasetstore"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyapply"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// AcquireSharedStoreLock takes the cooperative read lock for offline reads.
var AcquireSharedStoreLock = storelock.AcquireShared

// RescueRunner runs policy commands directly against a stopped daemon's
// store. Reads hold the shared store lock; apply and remove hold the
// exclusive lock and commit through the same rules as the daemon. With no
// signer running, nothing else reconciles the generation store, so apply
// and remove reconcile it first, as every unlock does.
type RescueRunner struct{}

// Run runs a validated command that needs the node, as OnlineRunner.Run
// does.
func (r RescueRunner) Run(ctx context.Context, command Command, streams Streams) error {
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

	return finishRescue(rescue(ctx, command, streams, paths, kr), guard.Normalize)
}

// rescue runs command against the store the keyring opened, reconciling it
// first when the command mutates.
func rescue(ctx context.Context, command Command, streams Streams, paths storepaths.Paths, kr *crypto.Keyring) error {
	if command.mutates() {
		report, err := genstore.ReconcileStoreRoot(paths, kr)
		for _, moved := range report.Moved() {
			_, _ = fmt.Fprintf(streams.Stderr, "reconciled: %s\n", moved)
		}
		if err != nil {
			return fmt.Errorf("reconcile the generation store: %w", err)
		}
	}
	backend, err := newOfflineBackend(command.DataDir, paths, kr)
	if err != nil {
		return err
	}
	if backend.tokenNote != "" {
		_, _ = fmt.Fprintln(streams.Stderr, "note: "+backend.tokenNote)
	}
	return run(ctx, command, streams, backend)
}

// finishRescue ends a rescue whose command returned runErr. A mutating
// rescue normalizes ownership on every outcome, as apstore's offline
// mutations do: what it wrote is root-owned when root runs it, a commit, a
// reconciliation, and a mint that failed after it published its successor
// or sealed the current generation alike. normalize does nothing for a
// read, or a store that is not managed.
func finishRescue(runErr error, normalize func() error) error {
	if err := normalize(); err != nil {
		if runErr != nil {
			return fmt.Errorf("%w; managed store ownership normalization also failed: %v", runErr, err)
		}
		return fmt.Errorf("managed store ownership normalization failed after the policy rescue: %w", err)
	}
	return runErr
}

// offlineBackend serves policy requests from the store itself.
type offlineBackend struct {
	env     policyapply.Env
	current *policyruntime.NodePolicy
	// tokenNames are the sources every selector with a token has one for,
	// read from the token files; nil when they are not known. tokenNote
	// says, when it is set, that a token file could not be read.
	tokenNames map[string][]string
	tokenNote  string
}

func newOfflineBackend(dataDir string, paths storepaths.Paths, kr *crypto.Keyring) (*offlineBackend, error) {
	cfg, err := serverconfig.LoadServerConfig(dataDir)
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
	if b.current, err = policyruntime.Load(b.env.Role, b.env.Config, active, b.env.Keyring); err != nil {
		return fmt.Errorf("verify active policy: %w", err)
	}
	if b.env.ASASet, err = asasetstore.Load(active, b.env.Keyring); err != nil {
		return fmt.Errorf("verify active asa set: %w", err)
	}
	// Rescue unlocked the store, so it reads which sources have a token from
	// the token files themselves, for the missing-token advisory.
	if b.env.Role == noderole.RoleCosigner {
		b.tokenNames, b.tokenNote = readSourceTokenNames(active, b.env.Keyring)
		b.env.SourceTokens = policyapply.SourceTokenNamesOf(b.tokenNames)
	}
	b.env.HeldKeys, err = policyapply.HeldPolicyKeysInGeneration(b.env.Role, active)
	return err
}

// readSourceTokenNames reads which sources have a token, by selector, for the
// missing-token advisory. Rescue exists for damaged stores and the names only
// feed an advisory, so this never fails a rescue: when any token file cannot
// be read, no names are known, as on a locked node, and note says which
// selectors' files could not be read (never what they hold) and how a
// damaged one is removed.
func readSourceTokenNames(active storepaths.GenPaths, kr *crypto.Keyring) (map[string][]string, string) {
	const unknown = "so source token names are not known and no missing-token warning is given"
	selectors, err := sourcetokens.Selectors(active)
	if err != nil {
		return nil, "the source token files could not be listed, " + unknown + "; run apstore verify to see why"
	}
	names := make(map[string][]string, len(selectors))
	var unreadable []string
	for _, selector := range selectors {
		f, ok, err := sourcetokens.ReadFile(active, selector, kr)
		if err != nil {
			unreadable = append(unreadable, selector)
			continue
		}
		if ok {
			for _, entry := range f.Listing() {
				names[selector] = append(names[selector], entry.Source)
			}
			f.Zero()
		}
	}
	if len(unreadable) == 0 {
		return names, ""
	}
	which := unreadable[0]
	if more := len(unreadable) - 1; more > 0 {
		which += fmt.Sprintf(" (and %d more)", more)
	}
	return nil, fmt.Sprintf("the source token file of %s could not be read, %s; "+
		"with the daemon stopped, apstore source token discard %s removes a damaged one", which, unknown, unreadable[0])
}

func (b *offlineBackend) Get(context.Context) (adminproto.PolicyView, error) {
	return policyapply.View(b.current, b.env.HeldKeys, ""), nil
}

func (b *offlineBackend) Context(context.Context) (adminproto.PolicyContextView, error) {
	return policyapply.ContextView(b.env, b.current), nil
}

func (b *offlineBackend) Document(_ context.Context, key, expectedSnapshot string) (adminproto.PolicyDocumentResult, error) {
	if expectedSnapshot != "" {
		if _, snapshot, err := policyapply.Snapshot(b.env, b.current); err != nil || snapshot != expectedSnapshot {
			return adminproto.PolicyDocumentResult{Key: key, Code: "policy_snapshot_changed", Error: "the node's policy or its context changed since the snapshot; read it again"}, nil
		}
	}
	return policyapply.Document(b.current, key), nil
}

// SourceTokenNames are the names read from the token files: nil, not known,
// on a signer and when a token file could not be read.
func (b *offlineBackend) SourceTokenNames(context.Context) (map[string][]string, error) {
	return b.tokenNames, nil
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
		if err := b.reload(); err != nil {
			return adminproto.ApplyPolicyResult{}, fmt.Errorf("policy applied as generation %s, but reloading it failed: %w", outcome.GenerationID, err)
		}
	}
	view := policyapply.View(b.current, b.env.HeldKeys, outcome.GenerationID)
	return adminproto.ApplyPolicyResult{Success: true, Policy: &view}, nil
}
