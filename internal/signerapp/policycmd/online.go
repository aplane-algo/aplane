// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

const OnlineTimeout = 10 * time.Second

// OnlineRunner runs policy commands against a running daemon over admin IPC.
type OnlineRunner struct {
	Session OnlineSession
}

func (r OnlineRunner) Run(ctx context.Context, command Command, streams Streams) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if r.Session == nil {
		return fmt.Errorf("admin policy session is required")
	}
	if err := RejectRetiredEnvironment(); err != nil {
		return err
	}
	streams = streams.normalized()
	passphrase, err := ReadPassphrase(streams.Stdin, streams.Stderr, command.readsStdin())
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
	return run(ctx, command, streams, onlineBackend{session: r.Session})
}

// onlineBackend sends policy requests to the daemon.
type onlineBackend struct {
	session OnlineSession
}

var onlineRequestSeq atomic.Uint64

func onlineRequestID(prefix string) string {
	return fmt.Sprintf("apadmin-%s-%d", prefix, onlineRequestSeq.Add(1))
}

func (b onlineBackend) Get(context.Context) (adminproto.PolicyView, error) {
	var msg protocol.PolicyMessage
	err := b.roundTrip(protocol.GetPolicyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetPolicy, ID: onlineRequestID("policy")},
	}, protocol.MsgTypePolicy, &msg)
	return viewFromWire(msg), err
}

func (b onlineBackend) Check(_ context.Context, req adminproto.CheckPolicyRequest) (adminproto.CheckPolicyResult, error) {
	var msg protocol.CheckPolicyResultMessage
	err := b.roundTrip(protocol.CheckPolicyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeCheckPolicy, ID: onlineRequestID("check-policy")},
		Documents:   documentsToWire(req.Documents),
		Remove:      req.Remove,
	}, protocol.MsgTypeCheckPolicyResult, &msg)
	return adminproto.CheckPolicyResult{
		Success: msg.Success, Valid: msg.Valid,
		Errors: problemsFromWire(msg.Errors), Warnings: problemsFromWire(msg.Warnings),
		Code: msg.Code, Error: msg.Error,
	}, err
}

func (b onlineBackend) Apply(_ context.Context, req adminproto.ApplyPolicyRequest) (adminproto.ApplyPolicyResult, error) {
	var msg protocol.ApplyPolicyResultMessage
	err := b.roundTrip(protocol.ApplyPolicyMessage{
		BaseMessage:             protocol.BaseMessage{Type: protocol.MsgTypeApplyPolicy, ID: onlineRequestID("apply-policy")},
		Documents:               documentsToWire(req.Documents),
		Remove:                  req.Remove,
		ExpectedPolicySetSHA256: req.ExpectedPolicySetSHA256,
	}, protocol.MsgTypeApplyPolicyResult, &msg)
	result := adminproto.ApplyPolicyResult{
		Success: msg.Success, Errors: problemsFromWire(msg.Errors),
		CommitUncertain: msg.CommitUncertain, Code: msg.Code, Error: msg.Error,
	}
	if msg.Policy != nil {
		view := viewFromWire(*msg.Policy)
		result.Policy = &view
	}
	return result, err
}

func (b onlineBackend) roundTrip(request any, wantType string, response any) error {
	raw, err := b.session.SendAndReceive(request, OnlineTimeout)
	if err != nil {
		return err
	}
	base, err := protocol.ParseAdminBaseMessage(raw)
	if err != nil {
		return err
	}
	if base.Type == protocol.MsgTypeError {
		var message protocol.ErrorMessage
		if err := json.Unmarshal(raw, &message); err != nil {
			return fmt.Errorf("decode admin error response: %w", err)
		}
		return protocol.WithCode(message.Code, fmt.Errorf("%s", strings.TrimSpace(message.Error)))
	}
	if base.Type != wantType {
		return fmt.Errorf("unexpected response type %q, want %q", base.Type, wantType)
	}
	return json.Unmarshal(raw, response)
}

func viewFromWire(msg protocol.PolicyMessage) adminproto.PolicyView {
	view := adminproto.PolicyView{
		Success: msg.Success, NodeRole: msg.NodeRole, PolicySetSHA256: msg.PolicySetSHA256,
		GenerationID: msg.GenerationID, Code: msg.Code, Error: msg.Error,
	}
	for _, doc := range msg.Documents {
		view.Documents = append(view.Documents, adminproto.PolicyDocument{
			Key: doc.Key, Document: doc.Document, SHA256: doc.SHA256, SignedAtUnix: doc.SignedAtUnix,
		})
	}
	for _, key := range msg.Keys {
		view.Keys = append(view.Keys, adminproto.PolicyKeyStatus{Key: key.Key, Status: key.Status})
	}
	return view
}

func documentsToWire(docs []adminproto.PolicyDocument) []protocol.PolicyDocumentWire {
	out := make([]protocol.PolicyDocumentWire, 0, len(docs))
	for _, doc := range docs {
		out = append(out, protocol.PolicyDocumentWire{Key: doc.Key, Document: doc.Document})
	}
	return out
}

func problemsFromWire(problems []protocol.PolicyProblemWire) []adminproto.PolicyProblem {
	var out []adminproto.PolicyProblem
	for _, problem := range problems {
		out = append(out, adminproto.PolicyProblem{Key: problem.Key, Pointer: problem.Pointer, Message: problem.Message})
	}
	return out
}

func authenticateAndUnlock(session OnlineSession, passphrase []byte) error {
	if err := session.Authenticate(string(passphrase), OnlineTimeout); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	status, err := session.WaitForStatus(OnlineTimeout)
	if err != nil {
		return fmt.Errorf("read signer status: %w", err)
	}
	if status.State != "locked" {
		return nil
	}
	result, err := session.Unlock(string(passphrase), OnlineTimeout)
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
