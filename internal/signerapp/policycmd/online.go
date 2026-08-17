// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
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
	return (loadedDocument{
		command: command, streams: streams, store: store, stored: stored,
		exactYAML: []byte(store.PolicyYAML()), target: target,
		status:  fmt.Sprintf("%s OK online", target.StatusNoun()),
		dataDir: "apsigner admin protocol", identityID: store.IdentityID(), editor: r.Editor,
	}).run()
}

func (r OnlineRunner) runDraft(ctx context.Context, command Command, streams Streams, store *policyeditor.AdminStore, target policyeditor.Target) error {
	parseTarget := target
	if command.Verb == VerbToSentry {
		parseTarget = policyeditor.TargetSigner
	}
	validator := &policyeditor.AdminStore{Client: store.Client, Target: parseTarget}
	data, stored, err := loadDraft(ctx, command, parseTarget, validator, streams.Stdin)
	if err != nil {
		return err
	}
	if command.Verb == VerbEdit {
		if _, err := store.Load(ctx); err != nil {
			return fmt.Errorf("load active %s before editing draft: %w", target.StatusNoun(), err)
		}
	}
	return (loadedDocument{
		command: command, streams: streams, store: store, stored: stored,
		exactYAML: data, target: parseTarget,
		status:  fmt.Sprintf("%s OK: %s", parseTarget.StatusNoun(), command.Source),
		dataDir: "apsigner admin protocol", identityID: store.IdentityID(), editor: r.Editor,
	}).run()
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

func identityOrDefault(identityID string) string {
	if strings.TrimSpace(identityID) == "" {
		return auth.CurrentProductIdentityID()
	}
	return identityID
}
