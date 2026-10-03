// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policycmd owns the application workflows behind apadmin policy
// commands. Command parsing and process exit remain in cmd/apadmin; the rules
// for checking and committing policy live in policyapply.
package policycmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

type Verb string

const (
	VerbStatus Verb = "status"
	VerbExport Verb = "export"
	VerbCheck  Verb = "check"
	VerbDiff   Verb = "diff"
	VerbApply  Verb = "apply"
	VerbRemove Verb = "remove"
)

var ProductionVerbs = []Verb{
	VerbStatus,
	VerbExport,
	VerbCheck,
	VerbDiff,
	VerbApply,
	VerbRemove,
}

func ParseVerb(raw string) (Verb, error) {
	verb := Verb(strings.ToLower(strings.TrimSpace(raw)))
	for _, candidate := range ProductionVerbs {
		if verb == candidate {
			return verb, nil
		}
	}
	return "", fmt.Errorf("unknown policy command %q", raw)
}

// Command is one parsed apadmin policy invocation. Args holds policy files
// for check, diff, and apply, or Witness Key IDs for remove. Key selects one
// cosigner document for export. Yes applies without asking for confirmation.
type Command struct {
	Verb    Verb
	Args    []string
	Key     string
	Yes     bool
	DataDir string
}

func (c Command) Validate() error {
	if _, err := ParseVerb(string(c.Verb)); err != nil {
		return err
	}
	switch c.Verb {
	case VerbStatus, VerbExport:
		if len(c.Args) > 0 {
			return fmt.Errorf("policy %s takes no arguments", c.Verb)
		}
	case VerbCheck, VerbDiff, VerbApply:
		if len(c.Args) == 0 {
			return fmt.Errorf("policy %s requires at least one policy file, or - for stdin", c.Verb)
		}
		for _, arg := range c.Args {
			if arg == "-" && len(c.Args) > 1 {
				return fmt.Errorf("policy %s reads stdin only as its sole file", c.Verb)
			}
		}
	case VerbRemove:
		if len(c.Args) == 0 {
			return fmt.Errorf("policy remove requires at least one Witness Key ID")
		}
	}
	if c.Key != "" && c.Verb != VerbExport {
		return fmt.Errorf("--key applies only to policy export")
	}
	if c.Yes && !c.mutates() {
		return fmt.Errorf("--yes applies only to policy apply and remove")
	}
	return nil
}

func (c Command) readsStdin() bool {
	return len(c.Args) == 1 && c.Args[0] == "-" && (c.Verb == VerbCheck || c.Verb == VerbDiff || c.Verb == VerbApply)
}

func (c Command) mutates() bool {
	return c.Verb == VerbApply || c.Verb == VerbRemove
}

type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func (s Streams) normalized() Streams {
	if s.Stdin == nil {
		s.Stdin = strings.NewReader("")
	}
	if s.Stdout == nil {
		s.Stdout = io.Discard
	}
	if s.Stderr == nil {
		s.Stderr = io.Discard
	}
	return s
}

// Backend reaches a node's policy, online through the daemon or offline
// through the store.
type Backend interface {
	Get(context.Context) (adminproto.PolicyView, error)
	Document(ctx context.Context, key string) (adminproto.PolicyDocumentResult, error)
	Check(context.Context, adminproto.CheckPolicyRequest) (adminproto.CheckPolicyResult, error)
	Apply(context.Context, adminproto.ApplyPolicyRequest) (adminproto.ApplyPolicyResult, error)
}

type OnlineSession interface {
	Dial() error
	Close()
	Authenticate(string, time.Duration) error
	WaitForStatus(time.Duration) (*protocol.StatusMessage, error)
	Unlock(string, time.Duration) (*protocol.UnlockResultMessage, error)
	SendAndReceive(interface{}, time.Duration) ([]byte, error)
}

type Runner interface {
	Run(context.Context, Command, Streams) error
}
