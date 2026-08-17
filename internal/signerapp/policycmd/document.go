// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

func loadDraft(ctx context.Context, command Command, target policyeditor.Target, store policyeditor.Store, stdin io.Reader) ([]byte, *policy.StoredConfig, error) {
	data, err := readSource(command.Source, stdin)
	if err != nil {
		return nil, nil, err
	}
	stored, err := target.Parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse %s: %w", target.DocumentName(), err)
	}
	if err := store.Validate(ctx, stored); err != nil {
		return nil, nil, err
	}
	return data, stored, nil
}

func readSource(source string, stdin io.Reader) ([]byte, error) {
	var data []byte
	var err error
	if source == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(source)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read policy YAML: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("policy YAML input is empty")
	}
	return data, nil
}

type loadedDocument struct {
	command    Command
	streams    Streams
	store      policyeditor.Store
	stored     *policy.StoredConfig
	exactYAML  []byte
	target     policyeditor.Target
	status     string
	dataDir    string
	identityID string
	editor     Editor
}

func (d loadedDocument) run() error {
	switch d.command.Verb {
	case VerbEdit:
		if d.editor == nil {
			return fmt.Errorf("policy editor is unavailable")
		}
		if d.status != "" {
			_, _ = fmt.Fprintln(d.streams.Stdout, d.status)
		}
		return d.editor(d.store, d.stored, d.dataDir, identityOrDefault(d.identityID), d.target)
	case VerbCheck:
		_, _ = fmt.Fprintln(d.streams.Stdout, d.status)
	case VerbExport:
		_, _ = d.streams.Stdout.Write(d.exactYAML)
	case VerbDigest:
		_, _ = fmt.Fprintln(d.streams.Stdout, policy.PolicySHA256(d.exactYAML))
	case VerbToSentry:
		converted, err := policy.ConvertSigningPolicyToSentryYAML(d.exactYAML)
		if err != nil {
			return fmt.Errorf("failed to convert policy to sentry policy: %w", err)
		}
		_, _ = d.streams.Stdout.Write(converted)
	default:
		return fmt.Errorf("unsupported policy command %q", d.command.Verb)
	}
	return nil
}
