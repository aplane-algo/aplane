// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeditor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const defaultProtocolRequestTimeout = 10 * time.Second

// AdminMessageRequester is the shared request boundary implemented by local
// IPC and the TUI's transport-neutral admin client.
type AdminMessageRequester interface {
	SendAndReceive(msg interface{}, timeout time.Duration) ([]byte, error)
}

// ProtocolClient adapts the admin wire protocol to AdminPolicyClient.
type ProtocolClient struct {
	requester AdminMessageRequester
	timeout   time.Duration
}

func NewProtocolClient(requester AdminMessageRequester, timeout time.Duration) *ProtocolClient {
	return &ProtocolClient{requester: requester, timeout: timeout}
}

func (c *ProtocolClient) GetPolicySnapshot(ctx context.Context, target Target) (AdminPolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return AdminPolicySnapshot{}, err
	}
	var out protocol.PolicySnapshotMessage
	err := c.request(protocol.GetPolicySnapshotMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeGetPolicySnapshot, ID: requestID("policy-snapshot")},
		Target:      string(target),
	}, &out)
	if err != nil {
		return AdminPolicySnapshot{}, err
	}
	return snapshotFromProtocol(out, target), nil
}

func (c *ProtocolClient) ValidatePolicy(ctx context.Context, target Target, policyYAML string) (AdminPolicyValidation, error) {
	if err := ctx.Err(); err != nil {
		return AdminPolicyValidation{}, err
	}
	var out protocol.ValidatePolicyResultMessage
	err := c.request(protocol.ValidatePolicyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeValidatePolicy, ID: requestID("policy-validate")},
		Target:      string(target),
		PolicyYAML:  policyYAML,
	}, &out)
	if err != nil {
		return AdminPolicyValidation{}, err
	}
	resultTarget := Target(out.Target)
	if resultTarget == "" {
		resultTarget = target
	}
	return AdminPolicyValidation{
		Success: out.Success, Target: resultTarget,
		Code: out.Code, Error: out.Error,
	}, nil
}

func (c *ProtocolClient) ReplacePolicy(ctx context.Context, target Target, policyYAML, expectedCurrentSHA256 string) (AdminPolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return AdminPolicySnapshot{}, err
	}
	var out protocol.ReplacePolicyResultMessage
	err := c.request(protocol.ReplacePolicyMessage{
		BaseMessage:           protocol.BaseMessage{Type: protocol.MsgTypeReplacePolicy, ID: requestID("policy-replace")},
		Target:                string(target),
		PolicyYAML:            policyYAML,
		ExpectedCurrentSHA256: expectedCurrentSHA256,
	}, &out)
	if err != nil {
		return AdminPolicySnapshot{}, err
	}
	return snapshotFromProtocol(protocol.PolicySnapshotMessage(out), target), nil
}

func (c *ProtocolClient) request(msg interface{}, out interface{}) error {
	if c == nil || c.requester == nil {
		return fmt.Errorf("admin client is not connected")
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = defaultProtocolRequestTimeout
	}
	raw, err := c.requester.SendAndReceive(msg, timeout)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func requestID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func snapshotFromProtocol(msg protocol.PolicySnapshotMessage, requested Target) AdminPolicySnapshot {
	target := Target(msg.Target)
	if target == "" {
		target = requested
	}
	return AdminPolicySnapshot{
		Success: msg.Success, Target: target,
		PolicyYAML: msg.PolicyYAML, PolicySHA256: msg.PolicySHA256,
		Canonical: msg.Canonical, Code: msg.Code, Error: msg.Error,
	}
}
