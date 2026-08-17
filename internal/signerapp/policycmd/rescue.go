// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

type RescueRunner struct {
	Editor Editor
}

func (r RescueRunner) Run(ctx context.Context, command Command, streams Streams) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if command.Remote {
		return fmt.Errorf("policy rescue is offline-only and cannot use --remote")
	}
	if err := RejectRetiredEnvironment(); err != nil {
		return err
	}
	streams = streams.normalized()
	target, err := rescueTarget(command)
	if err != nil {
		return err
	}
	if command.Source != "" && command.Verb != VerbApply {
		return r.runDraft(ctx, command, streams, target)
	}
	if command.DataDir == "" {
		return fmt.Errorf("signer data directory is required for production policy rescue")
	}
	return r.runProduction(ctx, command, streams, target)
}

func (r RescueRunner) runDraft(ctx context.Context, command Command, streams Streams, target policyeditor.Target) error {
	parseTarget := target
	if command.Verb == VerbToSentry {
		parseTarget = policyeditor.TargetSigner
	}
	fileStore := &policyeditor.FileStore{Path: command.Source, Target: parseTarget, DataDir: command.DataDir}
	data, stored, err := loadDraft(ctx, command, parseTarget, fileStore, streams.Stdin)
	if err != nil {
		return err
	}
	return (loadedDocument{
		command: command, streams: streams, store: fileStore, stored: stored,
		exactYAML: data, target: parseTarget,
		status:  fmt.Sprintf("%s OK: %s", parseTarget.StatusNoun(), command.Source),
		dataDir: command.Source, editor: r.Editor,
	}).run()
}

func (r RescueRunner) runProduction(ctx context.Context, command Command, streams Streams, target policyeditor.Target) error {
	cache := &passphraseCache{stdin: streams.Stdin, stderr: streams.Stderr, stdinReserved: command.Verb == VerbApply && command.Source == "-"}
	defer cache.Clear()
	store := &policyeditor.OfflineStore{
		DataDir:            command.DataDir,
		Target:             target,
		PassphraseProvider: cache.Get,
	}
	defer store.ClearPassphrase()

	if command.Verb == VerbApply {
		passphrase, err := cache.Get(ctx)
		if err != nil {
			return err
		}
		store.SetPassphrase(passphrase)
		crypto.ZeroBytes(passphrase)
		guard, err := AcquireOfflineMutation(command.DataDir)
		if err != nil {
			return fmt.Errorf("refusing offline policy apply: %w", err)
		}
		defer guard.Close()
		if err := guard.Bind(store); err != nil {
			return fmt.Errorf("refusing offline policy apply: %w", err)
		}
		data, err := readSource(command.Source, streams.Stdin)
		if err != nil {
			return err
		}
		if err := store.SaveYAML(ctx, data); err != nil {
			return err
		}
		if err := guard.Normalize(); err != nil {
			return fmt.Errorf("policy saved, but managed store ownership normalization failed: %w", err)
		}
		_, _ = fmt.Fprintf(streams.Stdout, "%s saved: %s\n", target.StatusNoun(), target.Path(command.DataDir, auth.CurrentProductIdentityID()))
		return nil
	}

	var guard *OfflineMutation
	if command.Verb == VerbEdit {
		var err error
		guard, err = AcquireOfflineMutation(command.DataDir)
		if err != nil {
			return fmt.Errorf("refusing offline policy editor: %w", err)
		}
		defer guard.Close()
		if err := guard.Bind(store); err != nil {
			return fmt.Errorf("refusing offline policy editor: %w", err)
		}
	}

	stored, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if passphrase := cache.Cached(); len(passphrase) > 0 {
		store.SetPassphrase(passphrase)
		crypto.ZeroBytes(passphrase)
	}
	identityID := auth.CurrentProductIdentityID()
	path := target.Path(command.DataDir, identityID)
	var data []byte
	if command.Verb == VerbExport || command.Verb == VerbDigest || command.Verb == VerbToSentry {
		data, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", target.DocumentName(), err)
		}
	}
	err = (loadedDocument{
		command: command, streams: streams, store: store, stored: stored,
		exactYAML: data, target: target,
		status:  fmt.Sprintf("%s OK: %s", target.StatusNoun(), path),
		dataDir: command.DataDir, identityID: identityID, editor: r.Editor,
	}).run()
	if err == nil && command.Verb == VerbEdit {
		err = guard.Normalize()
	}
	return err
}

func rescueTarget(command Command) (policyeditor.Target, error) {
	if command.Verb == VerbToSentry {
		return policyeditor.TargetSigner, nil
	}
	if command.Target == "" || command.Target == policyeditor.TargetAuto {
		if command.Source != "" && command.Verb != VerbApply && command.DataDir == "" {
			return policyeditor.TargetSigner, nil
		}
		return policyeditor.ResolveTarget(command.DataDir, policyeditor.TargetAuto)
	}
	return policyeditor.ResolveTarget(command.DataDir, command.Target)
}

type passphraseCache struct {
	stdin         io.Reader
	stderr        io.Writer
	stdinReserved bool
	passphrase    []byte
}

func (p *passphraseCache) Get(context.Context) ([]byte, error) {
	if len(p.passphrase) == 0 {
		passphrase, err := ReadPassphrase(p.stdin, p.stderr, false, p.stdinReserved)
		if err != nil {
			return nil, err
		}
		p.passphrase = append([]byte(nil), passphrase...)
		crypto.ZeroBytes(passphrase)
	}
	return append([]byte(nil), p.passphrase...), nil
}

func (p *passphraseCache) Cached() []byte {
	return append([]byte(nil), p.passphrase...)
}

func (p *passphraseCache) Clear() {
	crypto.ZeroBytes(p.passphrase)
	p.passphrase = nil
}
