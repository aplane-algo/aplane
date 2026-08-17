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
	"github.com/aplane-algo/aplane/internal/policy"
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
	data, err := readSource(command.Source, streams.Stdin)
	if err != nil {
		return err
	}
	parseTarget := target
	if command.Verb == VerbToSentry {
		parseTarget = policyeditor.TargetSigner
	}
	stored, err := parseTarget.Parse(data)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", parseTarget.DocumentName(), err)
	}
	fileStore := &policyeditor.FileStore{Path: command.Source, Target: parseTarget, DataDir: command.DataDir}
	if err := fileStore.Validate(ctx, stored); err != nil {
		return err
	}
	switch command.Verb {
	case VerbEdit:
		if r.Editor == nil {
			return fmt.Errorf("policy editor is unavailable")
		}
		_, _ = fmt.Fprintf(streams.Stdout, "%s OK: %s\n", parseTarget.StatusNoun(), command.Source)
		return r.Editor(fileStore, stored, command.Source, auth.CurrentProductIdentityID(), parseTarget)
	case VerbCheck:
		_, _ = fmt.Fprintf(streams.Stdout, "%s OK: %s\n", parseTarget.StatusNoun(), command.Source)
	case VerbExport:
		_, _ = streams.Stdout.Write(data)
	case VerbDigest:
		_, _ = fmt.Fprintln(streams.Stdout, policy.PolicySHA256(data))
	case VerbToSentry:
		converted, err := policy.ConvertSigningPolicyToSentryYAML(data)
		if err != nil {
			return fmt.Errorf("failed to convert policy to sentry policy: %w", err)
		}
		_, _ = streams.Stdout.Write(converted)
	default:
		return fmt.Errorf("unsupported standalone policy command %q", command.Verb)
	}
	return nil
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
	path := target.Path(command.DataDir, auth.CurrentProductIdentityID())
	switch command.Verb {
	case VerbEdit:
		if r.Editor == nil {
			return fmt.Errorf("policy editor is unavailable")
		}
		_, _ = fmt.Fprintf(streams.Stdout, "%s OK: %s\n", target.StatusNoun(), path)
		if err := r.Editor(store, stored, command.DataDir, auth.CurrentProductIdentityID(), target); err != nil {
			return err
		}
		if err := guard.Normalize(); err != nil {
			return fmt.Errorf("managed store ownership normalization failed: %w", err)
		}
	case VerbCheck:
		_, _ = fmt.Fprintf(streams.Stdout, "%s OK: %s\n", target.StatusNoun(), path)
	case VerbExport:
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", target.DocumentName(), err)
		}
		_, _ = streams.Stdout.Write(data)
	case VerbDigest:
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", target.DocumentName(), err)
		}
		_, _ = fmt.Fprintln(streams.Stdout, policy.PolicySHA256(data))
	case VerbToSentry:
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read policy YAML: %w", err)
		}
		converted, err := policy.ConvertSigningPolicyToSentryYAML(data)
		if err != nil {
			return fmt.Errorf("failed to convert policy to sentry policy: %w", err)
		}
		_, _ = streams.Stdout.Write(converted)
	default:
		return fmt.Errorf("unsupported production policy command %q", command.Verb)
	}
	return nil
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
