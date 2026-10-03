// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyruntime

import (
	"fmt"
	"os"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/asametadata"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// DefaultConfig returns the signer-runtime default policy with process
// genesis-hash mappings and local ASA amount formatting installed.
func DefaultConfig(dataDir string, serverCfg *serverconfig.ServerConfig) (*policy.Config, error) {
	resolver := apconfig.DefaultGenesisHashNetworkResolver()
	if serverCfg != nil {
		configured, err := apconfig.NewGenesisHashNetworkResolver(serverCfg.GenesisHashNetworks)
		if err != nil {
			return nil, err
		}
		resolver = configured
	}
	cfg := policy.DefaultConfigWithGenesisHashResolver(resolver)
	cfg.FormatASAAmount = asametadata.NewStore(dataDir).Formatter()
	return cfg, nil
}

// NodePolicy is a node's verified policy: the exact stored documents and the
// compiled policies the signing path enforces. A NodePolicy is immutable once
// built; readers clone the compiled configs they hand out.
type NodePolicy struct {
	Role noderole.Role
	// Documents holds the signer document, or one document per cosigner key
	// sorted by Witness Key ID.
	Documents []policy.StoredDocument
	// Signer is the compiled signer policy (signer nodes only).
	Signer *policy.Config
	// Cosigner maps each Witness Key ID with a document to its compiled
	// policy (cosigner nodes only). A key without an entry rejects every
	// request.
	Cosigner map[string]*policy.Config
}

// SetSHA256 digests the node's complete policy document set.
func (p *NodePolicy) SetSHA256() string {
	if p == nil {
		return policy.PolicySetSHA256(nil)
	}
	return policy.PolicySetSHA256(p.Documents)
}

// SignerConfig returns a copy of the compiled signer policy, or nil.
func (p *NodePolicy) SignerConfig() *policy.Config {
	if p == nil || p.Signer == nil {
		return nil
	}
	return p.Signer.Clone()
}

// CosignerConfigs returns copies of the compiled cosigner policies.
func (p *NodePolicy) CosignerConfigs() map[string]*policy.Config {
	if p == nil || p.Cosigner == nil {
		return nil
	}
	out := make(map[string]*policy.Config, len(p.Cosigner))
	for key, cfg := range p.Cosigner {
		out[key] = cfg.Clone()
	}
	return out
}

// Load verifies, decodes, and compiles the role's policy documents from one
// already-resolved generation. Any document that fails verification or
// validation fails the whole load.
func Load(role noderole.Role, dataDir string, serverCfg *serverconfig.ServerConfig, active storepaths.ActivePaths, kr *crypto.Keyring) (*NodePolicy, error) {
	switch role {
	case noderole.RoleSigner:
		if err := requireNoCosignerPolicies(active); err != nil {
			return nil, err
		}
		doc, _, err := policy.LoadVerifiedSignerPolicy(active, kr)
		if err != nil {
			return nil, err
		}
		return Compile(role, dataDir, serverCfg, []policy.StoredDocument{doc})
	case noderole.RoleCosigner:
		if err := requireNoSignerPolicy(active); err != nil {
			return nil, err
		}
		loaded, err := policy.LoadVerifiedCosignerPolicies(active, kr)
		if err != nil {
			return nil, err
		}
		docs := make([]policy.StoredDocument, 0, len(loaded))
		for _, entry := range loaded {
			docs = append(docs, entry.Document)
		}
		return Compile(role, dataDir, serverCfg, docs)
	default:
		return nil, fmt.Errorf("unsupported node role %q", role)
	}
}

// Compile decodes and compiles exact policy documents for role without
// touching storage. A signer node takes exactly one document; a cosigner node
// takes any number, each carrying its Witness Key ID.
func Compile(role noderole.Role, dataDir string, serverCfg *serverconfig.ServerConfig, docs []policy.StoredDocument) (*NodePolicy, error) {
	defaults, err := DefaultConfig(dataDir, serverCfg)
	if err != nil {
		return nil, err
	}
	out := &NodePolicy{Role: role, Documents: cloneDocuments(docs)}
	switch role {
	case noderole.RoleSigner:
		if len(docs) != 1 || docs[0].Key != "" {
			return nil, fmt.Errorf("a signer node takes exactly one policy document")
		}
		decoded, err := policy.DecodeSignerPolicyV1(docs[0].Bytes)
		if err != nil {
			return nil, err
		}
		if out.Signer, err = decoded.Compile(defaults); err != nil {
			return nil, err
		}
	case noderole.RoleCosigner:
		out.Cosigner = make(map[string]*policy.Config, len(docs))
		for _, doc := range docs {
			if _, dup := out.Cosigner[doc.Key]; dup {
				return nil, fmt.Errorf("duplicate policy document for cosigner key %s", doc.Key)
			}
			decoded, err := policy.DecodeCosignerPolicyV1(doc.Bytes, doc.Key)
			if err != nil {
				return nil, fmt.Errorf("cosigner key %s: %w", doc.Key, err)
			}
			cfg, err := decoded.Compile(defaults)
			if err != nil {
				return nil, fmt.Errorf("cosigner key %s: %w", doc.Key, err)
			}
			out.Cosigner[doc.Key] = cfg
		}
	default:
		return nil, fmt.Errorf("unsupported node role %q", role)
	}
	return out, nil
}

func cloneDocuments(docs []policy.StoredDocument) []policy.StoredDocument {
	out := make([]policy.StoredDocument, len(docs))
	for i, doc := range docs {
		out[i] = policy.StoredDocument{Key: doc.Key, Bytes: append([]byte(nil), doc.Bytes...), SignedAtUnix: doc.SignedAtUnix}
	}
	return out
}

func requireNoCosignerPolicies(active storepaths.ActivePaths) error {
	keys, err := policy.CosignerPolicyKeys(active)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return fmt.Errorf("signer node generation contains cosigner policy documents")
	}
	return nil
}

func requireNoSignerPolicy(active storepaths.ActivePaths) error {
	for _, path := range []string{active.PolicyPath(), policy.PolicyIntegritySidecarPath(active.PolicyPath())} {
		if exists, err := pathExists(path); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("cosigner node generation contains a signer policy document")
		}
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
