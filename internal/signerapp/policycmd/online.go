// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

const OnlineTimeout = 10 * time.Second

type OnlineRunner struct {
	Session OnlineSession
	Editor  Editor
}

func (r OnlineRunner) Run(ctx context.Context, command Command, streams Streams) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if command.Verb == VerbApply && command.Source == "" {
		return fmt.Errorf("policy apply requires a YAML file or - for stdin")
	}
	if r.Session == nil {
		return fmt.Errorf("admin policy session is required")
	}
	if err := RejectRetiredEnvironment(); err != nil {
		return err
	}
	streams = streams.normalized()
	passphrase, err := ReadPassphrase(streams.Stdin, streams.Stderr, command.Remote, command.Verb == VerbApply && command.Source == "-")
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(passphrase)

	if err := r.Session.Dial(); err != nil {
		return err
	}
	defer r.Session.Close()
	if err := authenticateAndUnlock(r.Session, passphrase); err != nil {
		return err
	}

	target := command.Target
	if command.Verb == VerbToSentry {
		target = policyeditor.TargetSigner
	} else if target == "" || target == policyeditor.TargetAuto {
		target, err = onlineTarget(r.Session)
		if err != nil {
			return err
		}
	}

	client := policyeditor.NewProtocolClient(r.Session, OnlineTimeout)
	store := &policyeditor.AdminStore{Client: client, Target: target}
	if command.Verb == VerbApply {
		if _, err := store.Load(ctx); err != nil {
			return fmt.Errorf("load active %s before apply: %w", target.StatusNoun(), err)
		}
		data, err := readSource(command.Source, streams.Stdin)
		if err != nil {
			return err
		}
		if err := store.SaveYAML(ctx, data); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(streams.Stdout, "%s saved online\n", target.StatusNoun())
		return nil
	}

	if command.Source != "" {
		return r.runDraft(ctx, command, streams, store, target)
	}
	stored, err := store.Load(ctx)
	if err != nil {
		return err
	}
	switch command.Verb {
	case VerbEdit:
		if r.Editor == nil {
			return fmt.Errorf("policy editor is unavailable")
		}
		return r.Editor(store, stored, "apsigner admin protocol", identityOrDefault(store.IdentityID()), target)
	case VerbCheck:
		_, _ = fmt.Fprintf(streams.Stdout, "%s OK online\n", target.StatusNoun())
	case VerbExport:
		_, _ = io.WriteString(streams.Stdout, store.PolicyYAML())
	case VerbDigest:
		_, _ = fmt.Fprintln(streams.Stdout, store.LastSHA256())
	case VerbToSentry:
		converted, err := policy.ConvertSigningPolicyToSentryYAML([]byte(store.PolicyYAML()))
		if err != nil {
			return fmt.Errorf("failed to convert policy: %w", err)
		}
		_, _ = streams.Stdout.Write(converted)
	default:
		return fmt.Errorf("unsupported policy command %q", command.Verb)
	}
	return nil
}

func (r OnlineRunner) runDraft(ctx context.Context, command Command, streams Streams, store *policyeditor.AdminStore, target policyeditor.Target) error {
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
	validator := &policyeditor.AdminStore{Client: store.Client, Target: parseTarget}
	if err := validator.Validate(ctx, stored); err != nil {
		return err
	}

	switch command.Verb {
	case VerbEdit:
		if _, err := store.Load(ctx); err != nil {
			return fmt.Errorf("load active %s before editing draft: %w", target.StatusNoun(), err)
		}
		if r.Editor == nil {
			return fmt.Errorf("policy editor is unavailable")
		}
		_, _ = fmt.Fprintf(streams.Stdout, "%s OK: %s\n", target.StatusNoun(), command.Source)
		return r.Editor(store, stored, "apsigner admin protocol", identityOrDefault(store.IdentityID()), target)
	case VerbCheck:
		_, _ = fmt.Fprintf(streams.Stdout, "%s OK: %s\n", target.StatusNoun(), command.Source)
	case VerbExport:
		_, _ = streams.Stdout.Write(data)
	case VerbDigest:
		_, _ = fmt.Fprintln(streams.Stdout, policy.PolicySHA256(data))
	case VerbToSentry:
		converted, err := policy.ConvertSigningPolicyToSentryYAML(data)
		if err != nil {
			return fmt.Errorf("failed to convert policy: %w", err)
		}
		_, _ = streams.Stdout.Write(converted)
	default:
		return fmt.Errorf("unsupported policy command %q", command.Verb)
	}
	return nil
}

func authenticateAndUnlock(session OnlineSession, passphrase []byte) error {
	secret := string(passphrase)
	if err := session.Authenticate(secret, OnlineTimeout); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	status, err := session.WaitForStatus(OnlineTimeout)
	if err != nil {
		return fmt.Errorf("read signer status: %w", err)
	}
	if status.State != "locked" {
		return nil
	}
	result, err := session.Unlock(secret, OnlineTimeout)
	if err != nil {
		return fmt.Errorf("unlock signer: %w", err)
	}
	if !result.Success {
		if result.Error != "" {
			return fmt.Errorf("unlock signer: %s", result.Error)
		}
		return fmt.Errorf("unlock signer failed")
	}
	return nil
}

func onlineTarget(requester interface {
	SendAndReceive(interface{}, time.Duration) ([]byte, error)
}) (policyeditor.Target, error) {
	id := fmt.Sprintf("apadmin-policy-settings-%d", time.Now().UnixNano())
	raw, err := requester.SendAndReceive(protocol.GetAdminSettingsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetAdminSettings, ID: id},
	}, OnlineTimeout)
	if err != nil {
		return "", err
	}
	base, err := protocol.ParseAdminBaseMessage(raw)
	if err != nil {
		return "", err
	}
	if base.Type == protocol.MsgTypeError {
		var message protocol.ErrorMessage
		if err := json.Unmarshal(raw, &message); err != nil {
			return "", fmt.Errorf("decode admin error response: %w", err)
		}
		detail := strings.TrimSpace(message.Error)
		if detail == "" {
			detail = "admin settings request failed"
		}
		return "", protocol.WithCode(message.Code, fmt.Errorf("load admin settings: %s", detail))
	}
	if base.Type != protocol.MsgTypeAdminSettings {
		return "", fmt.Errorf("load admin settings: unexpected response type %q", base.Type)
	}
	var settings protocol.AdminSettingsMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		return "", err
	}
	if strings.EqualFold(strings.TrimSpace(settings.NodeRole), "sentry") {
		return policyeditor.TargetSentry, nil
	}
	return policyeditor.TargetSigner, nil
}

func readSource(source string, stdin io.Reader) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	if source == "-" {
		data, err = io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy YAML from stdin: %w", err)
		}
	} else {
		data, err = os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy YAML file: %w", err)
		}
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("policy YAML input is empty")
	}
	return data, nil
}

func identityOrDefault(identityID string) string {
	if strings.TrimSpace(identityID) == "" {
		return auth.CurrentProductIdentityID()
	}
	return identityID
}
