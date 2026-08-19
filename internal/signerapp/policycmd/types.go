// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policycmd owns the application workflows behind apadmin policy
// commands. Command parsing and process exit remain in cmd/apadmin; policy
// schemas, persistence, and the editor remain in their existing owning
// packages.
package policycmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

type Verb string

const (
	VerbEdit     Verb = "edit"
	VerbCheck    Verb = "check"
	VerbExport   Verb = "export"
	VerbDigest   Verb = "digest"
	VerbApply    Verb = "apply"
	VerbToSentry Verb = "to-sentry"
)

var ProductionVerbs = []Verb{
	VerbEdit,
	VerbCheck,
	VerbExport,
	VerbDigest,
	VerbApply,
	VerbToSentry,
}

func ParseVerb(raw string) (Verb, error) {
	if strings.TrimSpace(raw) == "" {
		return VerbEdit, nil
	}
	verb := Verb(strings.ToLower(strings.TrimSpace(raw)))
	for _, candidate := range ProductionVerbs {
		if verb == candidate {
			return verb, nil
		}
	}
	return "", fmt.Errorf("unknown policy command %q", raw)
}

type Command struct {
	Verb    Verb
	Target  policyeditor.Target
	Source  string
	DataDir string
	Remote  bool
}

func (c Command) Validate() error {
	if _, err := ParseVerb(string(c.Verb)); err != nil {
		return err
	}
	if c.Target == "" {
		c.Target = policyeditor.TargetAuto
	}
	if _, err := policyeditor.ParseTarget(string(c.Target)); err != nil {
		return err
	}
	if c.Verb == VerbApply && c.Source == "" {
		return fmt.Errorf("policy apply requires a YAML file or - for stdin")
	}
	if c.Verb != VerbApply && c.Source == "-" {
		return fmt.Errorf("policy %s does not read YAML from stdin; provide a file", c.Verb)
	}
	if c.Verb == VerbToSentry && c.Target == policyeditor.TargetSentry {
		return fmt.Errorf("policy to-sentry requires signer-policy input; --target sentry is invalid")
	}
	return nil
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

type Editor func(policyeditor.Store, *policy.StoredConfig, string, policyeditor.Target) error

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
