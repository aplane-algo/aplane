// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyruntime

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/asaset"
	"github.com/aplane-algo/aplane/internal/asasetstore"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// DefaultConfig returns the compile base for this node: process genesis-hash
// mappings, and ASA amounts in limit messages shown from ctx, the node's
// policy context (base units only when ctx is nil). Every verdict field is
// replaced when a document compiles onto it.
func DefaultConfig(serverCfg *serverconfig.ServerConfig, ctx *policycontext.Context) (*policy.Config, error) {
	resolver := apconfig.DefaultGenesisHashNetworkResolver()
	if serverCfg != nil {
		configured, err := apconfig.NewGenesisHashNetworkResolver(serverCfg.GenesisHashNetworks)
		if err != nil {
			return nil, err
		}
		resolver = configured
	}
	cfg := policy.DefaultConfigWithGenesisHashResolver(resolver)
	if ctx != nil {
		cfg.FormatASAAmount = func(network string, assetID, raw uint64) (string, bool) {
			a, ok := ctx.Asset(network, assetID)
			if !ok {
				return "", false
			}
			return a.Display(raw), true
		}
	}
	return cfg, nil
}

// NodePolicy is a node's verified policy: the exact stored documents and the
// compiled policies the signing path enforces. A NodePolicy is immutable once
// built, and so are the configs it hands out.
type NodePolicy struct {
	Role noderole.Role
	// Documents holds the node default first, then one document per key
	// with a policy of its own, sorted by key.
	Documents []policy.StoredDocument
	// Default is the compiled node default: the policy of every key without
	// a document of its own.
	Default *policy.Config
	// Keys maps each key with a document of its own to its compiled policy.
	Keys map[string]*policy.Config
	// Context is the policy context the documents were compiled in: the
	// node's networks and effective ASA set when they were loaded. A signing
	// request that captures this NodePolicy shows amounts from it, in limit
	// messages and approval prompts alike, whatever reloads land later. It is
	// nil for documents compiled without one.
	Context *policycontext.Context
}

// SetSHA256 digests the node's complete policy document set.
func (p *NodePolicy) SetSHA256() string {
	if p == nil {
		return policy.PolicySetSHA256(nil)
	}
	return policy.PolicySetSHA256(p.Documents)
}

// PolicyFor returns the policy that governs selector: the key's own, or the
// node default. It is nil only before policy loads. The returned Config is
// shared and must not be modified.
func (p *NodePolicy) PolicyFor(selector string) *policy.Config {
	if p == nil {
		return nil
	}
	if cfg, ok := p.Keys[selector]; ok && selector != "" {
		return cfg
	}
	return p.Default
}

// HasOwn reports whether selector has a policy document of its own.
func (p *NodePolicy) HasOwn(selector string) bool {
	if p == nil {
		return false
	}
	_, ok := p.Keys[selector]
	return ok
}

// Load verifies, decodes, and compiles the role's policy documents from one
// already-resolved generation, in the context of that generation's verified
// ASA set and the configured networks. Any document that fails verification
// or validation fails the whole load, as does a generation with no default
// or an ASA set that does not verify.
func Load(role noderole.Role, serverCfg *serverconfig.ServerConfig, active storepaths.ActivePaths, kr *crypto.Keyring) (*NodePolicy, error) {
	def, _, err := policy.LoadVerifiedDefault(active, role, kr)
	if err != nil {
		return nil, err
	}
	loaded, err := policy.LoadVerifiedKeyPolicies(active, role, kr)
	if err != nil {
		return nil, err
	}
	docs := make([]policy.StoredDocument, 0, 1+len(loaded))
	docs = append(docs, def)
	for _, entry := range loaded {
		docs = append(docs, entry.Document)
	}
	set, err := asasetstore.Load(active, kr)
	if err != nil {
		return nil, err
	}
	ctx, err := NewContext(role, serverCfg, set)
	if err != nil {
		return nil, err
	}
	return Compile(role, serverCfg, docs, ctx)
}

// NewContext is the policy context of a node of role with serverCfg's
// networks and the operator confirmations set.
func NewContext(role noderole.Role, serverCfg *serverconfig.ServerConfig, set *asaset.Set) (*policycontext.Context, error) {
	var custom map[string]string
	if serverCfg != nil {
		custom = serverCfg.GenesisHashNetworks
	}
	networks, err := apconfig.NewGenesisHashNetworkResolver(custom)
	if err != nil {
		return nil, err
	}
	if set == nil {
		set = asaset.Empty()
	}
	return policycontext.New(role, networks, set)
}

// Compile decodes and compiles exact policy documents for role without
// touching storage. docs must hold exactly one document with the key
// policy.DefaultKey and at most one per key selector.
func Compile(role noderole.Role, serverCfg *serverconfig.ServerConfig, docs []policy.StoredDocument, ctx *policycontext.Context) (*NodePolicy, error) {
	if role != noderole.RoleSigner && role != noderole.RoleCosigner {
		return nil, fmt.Errorf("unsupported node role %q", role)
	}
	defaults, err := DefaultConfig(serverCfg, ctx)
	if err != nil {
		return nil, err
	}
	out := &NodePolicy{Role: role, Keys: make(map[string]*policy.Config, len(docs)), Context: ctx}
	var ordered []policy.StoredDocument
	for _, doc := range docs {
		if doc.Key == policy.DefaultKey {
			if out.Default != nil {
				return nil, fmt.Errorf("duplicate default policy document")
			}
			decoded, err := policy.DecodePolicyV1(doc.Bytes, policy.DefaultKey, role)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", storepaths.DefaultPolicyFileName, err)
			}
			if out.Default, err = decoded.Compile(defaults); err != nil {
				return nil, fmt.Errorf("%s: %w", storepaths.DefaultPolicyFileName, err)
			}
			ordered = append([]policy.StoredDocument{cloneDocument(doc)}, ordered...)
			continue
		}
		if _, dup := out.Keys[doc.Key]; dup {
			return nil, fmt.Errorf("duplicate policy document for key %s", doc.Key)
		}
		decoded, err := policy.DecodePolicyV1(doc.Bytes, doc.Key, role)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", doc.Key, err)
		}
		cfg, err := decoded.Compile(defaults)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", doc.Key, err)
		}
		out.Keys[doc.Key] = cfg
		ordered = append(ordered, cloneDocument(doc))
	}
	if out.Default == nil {
		return nil, fmt.Errorf("the node has no default policy document")
	}
	out.Documents = ordered
	return out, nil
}

func cloneDocument(doc policy.StoredDocument) policy.StoredDocument {
	return policy.StoredDocument{Key: doc.Key, Bytes: append([]byte(nil), doc.Bytes...), SignedAtUnix: doc.SignedAtUnix}
}
