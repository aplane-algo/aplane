// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policyadmission"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

// NodeContext is the node a workspace's documents are for, as an export of
// it describes: its role, networks and ASA set. A workspace with one checks
// its documents against that node, and reports what the node would refuse to
// admit as errors. It is an offline snapshot; the node may have moved on,
// which apadmin policy apply checks.
type NodeContext struct {
	Context    *policycontext.Context
	ExportedAt time.Time
	// Path is the context file it was read from.
	Path string
}

// Describe says where the context comes from and how old it is, for a
// result or a status line.
func (n *NodeContext) Describe(now time.Time) string {
	if n == nil {
		return "built-in networks and assets only; no node context"
	}
	return fmt.Sprintf("the %s node exported to %s %s ago (an offline snapshot)",
		n.Context.Role(), n.Path, age(now.Sub(n.ExportedAt)))
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d day(s)", int(d/(24*time.Hour)))
	}
}

// Networks is the node's network mapping, exactly as exported: the editor's
// own built-in networks are not merged in.
func (n *NodeContext) Networks(now time.Time) (Networks, error) {
	if n == nil {
		return BuiltinNetworks(), nil
	}
	byHash := map[string]string{}
	for token, genesis := range n.Context.Networks() {
		byHash[genesis.String()] = token
	}
	resolver, err := apconfig.GenesisHashNetworkResolverOf(byHash)
	if err != nil {
		return Networks{}, err
	}
	return Networks{Resolver: resolver, Source: "networks of " + n.Describe(now)}, nil
}

// Lookup is the node's ASA table, exactly as exported, for labels and
// amounts; without a node context, the built-in table.
func (n *NodeContext) Lookup() AssetLookup {
	if n == nil {
		return asa.BuiltinMetadata
	}
	ctx := n.Context
	return func(network string, assetID uint64) (asa.Metadata, bool) {
		a, ok := ctx.Asset(network, assetID)
		if !ok {
			return asa.Metadata{}, false
		}
		source := asa.SourceBuiltin
		if a.Origin == asaset.OriginOperator {
			source = "confirmed on the node"
		}
		return asa.Metadata{Network: network, AssetID: assetID, Name: a.Name, UnitName: a.UnitName, Decimals: a.Decimals, Source: source}, true
	}
}

// builtinContext is what an editor knows of a role's node without its
// export: the built-in networks and assets.
func builtinContext(role noderole.Role) *policycontext.Context {
	ctx, err := policycontext.New(role, apconfig.DefaultGenesisHashNetworkResolver(), asaset.Empty())
	if err != nil {
		return nil
	}
	return ctx
}

// checkAdmission adds the problems a node would raise when admitting f's
// document. Against a node context they are errors, since the node refuses
// what they describe; against the built-in tables alone they are warnings,
// since the node may know a network or asset the editor does not.
func (w *Workspace) checkAdmission(f *File) {
	if f.Document == nil || f.Role == "" {
		return
	}
	severity, ctx, note := SeverityWarning, builtinContext(f.Role), " (checked against the built-in networks and assets only; open an export of the node to check against its own)"
	if w.Node != nil {
		if f.Role != w.Node.Context.Role() {
			return
		}
		severity, ctx, note = SeverityError, w.Node.Context, ""
	}
	if ctx == nil {
		return
	}
	for _, p := range policyadmission.Check(f.Document, ctx) {
		w.Problems = append(w.Problems, Problem{Path: f.Path, Pointer: p.Pointer, Severity: severity, RuleID: p.RuleID, Message: p.Message + note})
	}
}
