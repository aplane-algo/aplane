// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policycontext is what a node's policy means in: its role, the
// chains its network tokens name, and its effective ASA set. The context is
// what policy documents are admitted against and what an editor needs to show
// them, so it travels with an export, and its digest lets an apply check that
// the node still has the context the documents were edited in.
//
// This package is pure. Building a context from a running node belongs to the
// signer's adapters.
package policycontext

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
)

// AdmissionRulesVersion is the version of the rules documents are admitted
// under. It is part of the context, so a change to the rules changes the
// context's digest.
const AdmissionRulesVersion = 1

// Context is a node's policy context. A Context is immutable.
type Context struct {
	role         noderole.Role
	networks     map[string]asaset.GenesisHash
	assets       *asaset.Table
	rulesVersion int
}

// New is the context of a node with role, whose network tokens resolve
// through networks (the built-in networks plus its custom mappings), and whose
// operator confirmations are set.
func New(role noderole.Role, networks apconfig.GenesisHashNetworkResolver, set *asaset.Set) (*Context, error) {
	if role != noderole.RoleSigner && role != noderole.RoleCosigner {
		return nil, fmt.Errorf("unsupported node role %q", role)
	}
	byToken := map[string]asaset.GenesisHash{}
	for hash, token := range networks.Map() {
		genesis, err := asaset.ParseGenesisHash(hash)
		if err != nil {
			return nil, fmt.Errorf("network %q: %w", token, err)
		}
		byToken[token] = genesis
	}
	return &Context{role: role, networks: byToken, assets: asaset.Effective(set), rulesVersion: AdmissionRulesVersion}, nil
}

// FromParts is a context of exactly these parts, such as one an export
// carries. networks maps each token to its chain.
func FromParts(role noderole.Role, networks map[string]asaset.GenesisHash, assets *asaset.Table, rulesVersion int) (*Context, error) {
	if role != noderole.RoleSigner && role != noderole.RoleCosigner {
		return nil, fmt.Errorf("unsupported node role %q", role)
	}
	if assets == nil {
		return nil, fmt.Errorf("a context needs an asset table")
	}
	byToken := make(map[string]asaset.GenesisHash, len(networks))
	for token, genesis := range networks {
		if err := apconfig.ValidateNetworkID(token); err != nil {
			return nil, err
		}
		byToken[token] = genesis
	}
	return &Context{role: role, networks: byToken, assets: assets, rulesVersion: rulesVersion}, nil
}

// Role is the node's role.
func (c *Context) Role() noderole.Role { return c.role }

// RulesVersion is the admission rules version the context was built for.
func (c *Context) RulesVersion() int { return c.rulesVersion }

// Assets is the effective ASA set: built-ins and confirmations.
func (c *Context) Assets() *asaset.Table { return c.assets }

// Networks returns the network tokens and the chain each names.
func (c *Context) Networks() map[string]asaset.GenesisHash {
	out := make(map[string]asaset.GenesisHash, len(c.networks))
	for token, genesis := range c.networks {
		out[token] = genesis
	}
	return out
}

// Chain returns the chain a network token names.
func (c *Context) Chain(token string) (asaset.GenesisHash, bool) {
	genesis, ok := c.networks[token]
	return genesis, ok
}

// Network returns the token that names a chain, if any does.
func (c *Context) Network(genesis asaset.GenesisHash) (string, bool) {
	for token, g := range c.networks {
		if g == genesis {
			return token, true
		}
	}
	return "", false
}

// Asset returns what the context knows about an asset named by a network
// token and an ID, as a policy document names it.
func (c *Context) Asset(token string, assetID uint64) (asaset.Asset, bool) {
	genesis, ok := c.networks[token]
	if !ok {
		return asaset.Asset{}, false
	}
	return c.assets.Lookup(asaset.Identity{Genesis: genesis, AssetID: assetID})
}

// Domain tags keep the two digests, and any later one, from colliding.
const (
	contextDigestDomain  = "aplane.policy-context.v1"
	snapshotDigestDomain = "aplane.policy-snapshot.v1"
)

// SHA256 is the hex digest of the context's meaning: the role, the rules
// version, every network token with its chain, and every asset with the
// fields admission, labels and amount conversion use (its identity, origin,
// decimals, unit name and name). Confirmation times, the token an asset was
// confirmed under, and the creator do not change what the context means, so
// they are left out.
//
// The encoding is a sequence of fields, each a length-prefixed byte string
// (an unsigned varint length, then the bytes) or a big-endian uint64, in a
// fixed order, so no two contexts share an encoding.
func (c *Context) SHA256() string {
	var e encoder
	e.text(contextDigestDomain)
	e.text(string(c.role))
	e.uint(uint64(c.rulesVersion))

	tokens := make([]string, 0, len(c.networks))
	for token := range c.networks {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	e.uint(uint64(len(tokens)))
	for _, token := range tokens {
		genesis := c.networks[token]
		e.text(token)
		e.bytes(genesis[:])
	}

	assets := c.assets.Assets()
	e.uint(uint64(len(assets)))
	for _, a := range assets {
		e.bytes(a.Genesis[:])
		e.uint(a.AssetID)
		e.text(string(a.Origin))
		e.uint(a.Decimals)
		e.text(a.UnitName)
		e.text(a.Name)
	}
	return e.sum()
}

// SnapshotSHA256 is the hex digest of a node's policy and its context
// together: the context digest and the policy set digest
// (policy.PolicySetSHA256) under their own domain. It changes when either
// does, and only then.
func SnapshotSHA256(contextSHA256, policySetSHA256 string) string {
	var e encoder
	e.text(snapshotDigestDomain)
	e.text(contextSHA256)
	e.text(policySetSHA256)
	return e.sum()
}

type encoder struct{ buf []byte }

func (e *encoder) bytes(b []byte) {
	e.buf = binary.AppendUvarint(e.buf, uint64(len(b)))
	e.buf = append(e.buf, b...)
}

func (e *encoder) text(s string) { e.bytes([]byte(s)) }

func (e *encoder) uint(n uint64) { e.buf = binary.BigEndian.AppendUint64(e.buf, n) }

func (e *encoder) sum() string {
	sum := sha256.Sum256(e.buf)
	return hex.EncodeToString(sum[:])
}
