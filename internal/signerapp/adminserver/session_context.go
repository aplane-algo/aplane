// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"context"
	"fmt"
	"github.com/aplane-algo/aplane/internal/adminproto"
	"sync/atomic"

	"github.com/aplane-algo/aplane/internal/auth"
)

const (
	TransportUnknown = "unknown"
	TransportIPC     = "ipc"
	TransportSSH     = "ssh"
)

var sessionIDCounter atomic.Uint64

// SessionPrincipal is an immutable snapshot of an authenticated actor.
type SessionPrincipal struct {
	ID       string
	Type     string
	Method   string
	Metadata map[string]string
}

// SessionContext carries attribution context for one admin session.
type SessionContext struct {
	SessionID          string
	AdminPrincipal     SessionPrincipal
	AuthMethod         string
	Transport          string
	RemoteAddr         string
	RequesterPrincipal SessionPrincipal
	ApproverPrincipal  SessionPrincipal
}

func newSessionContext(method string, conn adminproto.AdminConn) SessionContext {
	return SessionContext{
		SessionID:  newSessionID(),
		AuthMethod: method,
		Transport:  TransportUnknown,
		RemoteAddr: connRemoteAddr(conn),
	}
}

func newSessionID() string {
	return fmt.Sprintf("admin-%d", sessionIDCounter.Add(1))
}

func connRemoteAddr(conn adminproto.AdminConn) string {
	if conn == nil {
		return ""
	}
	return conn.RemoteAddr()
}

func principalFromIdentity(id *auth.Identity) SessionPrincipal {
	if id == nil {
		return SessionPrincipal{}
	}
	return SessionPrincipal{
		ID:       id.ID,
		Type:     id.Type,
		Method:   id.Method,
		Metadata: cloneStringMap(id.Metadata),
	}
}

func cloneSessionContext(ctx SessionContext) SessionContext {
	ctx.AdminPrincipal.Metadata = cloneStringMap(ctx.AdminPrincipal.Metadata)
	ctx.RequesterPrincipal.Metadata = cloneStringMap(ctx.RequesterPrincipal.Metadata)
	ctx.ApproverPrincipal.Metadata = cloneStringMap(ctx.ApproverPrincipal.Metadata)
	return ctx
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type sessionContextKey struct{}

// WithSessionContext returns ctx carrying the admin session's attribution, so
// services that log on the session's behalf can attribute the event.
func WithSessionContext(ctx context.Context, session SessionContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sessionContextKey{}, cloneSessionContext(session))
}

// SessionContextFromContext returns the admin session attribution that
// WithSessionContext attached to ctx.
func SessionContextFromContext(ctx context.Context) (SessionContext, bool) {
	if ctx == nil {
		return SessionContext{}, false
	}
	session, ok := ctx.Value(sessionContextKey{}).(SessionContext)
	return session, ok
}
