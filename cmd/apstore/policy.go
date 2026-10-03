// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyapply"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func cmdPolicy(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: apstore policy <check|verify|sign>")
	}
	switch args[0] {
	case "check":
		return cmdPolicyCheck()
	case "verify":
		return cmdPolicyVerify()
	case "sign":
		return cmdPolicySign()
	default:
		return fmt.Errorf("usage: apstore policy <check|verify|sign>")
	}
}

// cmdPolicyCheck validates every stored policy document without verifying
// sidecars, so hand-placed documents can be reviewed before signing, and
// reports cosigner keys and documents that do not match.
func cmdPolicyCheck() error {
	active, kr, err := readStore()
	if err != nil {
		return err
	}
	defer kr.Zero()
	role, err := storeNodeRole()
	if err != nil {
		return err
	}
	docs, err := storedPolicyDocuments(active, role)
	if err != nil {
		return err
	}
	if _, err := policyruntime.Compile(role, dataDirectory, &config, docs); err != nil {
		return fmt.Errorf("policy invalid: %w", err)
	}
	for _, doc := range docs {
		path := policyDocumentPath(active, doc.Key)
		sidecarBytes, err := os.ReadFile(policy.PolicyIntegritySidecarPath(path))
		switch {
		case os.IsNotExist(err):
			logWarnf("%s has no sidecar; run apstore policy sign after reviewing it", path)
		case err != nil:
			return fmt.Errorf("read sidecar for %s: %w", path, err)
		default:
			if _, err := policy.ParsePolicyIntegritySidecar(sidecarBytes); err != nil {
				return fmt.Errorf("parse sidecar for %s: %w", path, err)
			}
		}
		logInfof("policy OK: %s", path)
	}
	if role == noderole.RoleCosigner {
		held, err := policyapply.HeldCosignerKeysInGeneration(active)
		if err != nil {
			return err
		}
		np := &policyruntime.NodePolicy{Role: role, Documents: docs}
		for _, warning := range policyapply.CoverageWarnings(policyapply.KeyStatus(held, np)) {
			logWarnf("%s: %s", warning.Key, warning.Message)
		}
	}
	return nil
}

func cmdPolicyVerify() error {
	active, kr, err := readStore()
	if err != nil {
		return err
	}
	defer kr.Zero()
	role, err := storeNodeRole()
	if err != nil {
		return err
	}
	np, err := policyruntime.Load(role, dataDirectory, &config, active, kr)
	if err != nil {
		return codedError{code: policyIntegrityFailedCode, message: fmt.Sprintf("policy verification failed: %v", err)}
	}
	for _, doc := range np.Documents {
		logInfof("policy verified: %s", policyDocumentPath(active, doc.Key))
	}
	return nil
}

// cmdPolicySign validates every stored policy document and replaces its
// sidecar, for documents placed or edited by hand while the daemon is stopped.
func cmdPolicySign() error {
	active, kr, err := readStore()
	if err != nil {
		return err
	}
	defer kr.Zero()
	role, err := storeNodeRole()
	if err != nil {
		return err
	}
	now := time.Now()
	switch role {
	case noderole.RoleSigner:
		err = policy.ResignSignerPolicy(active, kr, now)
	case noderole.RoleCosigner:
		err = policy.ResignCosignerPolicies(active, kr, now)
	default:
		err = fmt.Errorf("unsupported node role %q", role)
	}
	if err != nil {
		return fmt.Errorf("sign policy sidecars: %w", err)
	}
	np, err := policyruntime.Load(role, dataDirectory, &config, active, kr)
	if err != nil {
		return codedError{code: policyIntegrityFailedCode, message: fmt.Sprintf("sidecars written but verification failed: %v", err)}
	}
	for _, doc := range np.Documents {
		logInfof("policy sidecar signed: %s", policy.PolicyIntegritySidecarPath(policyDocumentPath(active, doc.Key)))
	}
	return nil
}

func storeNodeRole() (noderole.Role, error) {
	doc, _, err := noderole.Load(storepaths.NewPaths(dataDirectory))
	if err != nil {
		return "", fmt.Errorf("failed to load node role: %w", err)
	}
	return doc.Role, nil
}

// storedPolicyDocuments reads the role's policy documents without verifying
// their sidecars.
func storedPolicyDocuments(active storepaths.GenPaths, role noderole.Role) ([]policy.StoredDocument, error) {
	switch role {
	case noderole.RoleSigner:
		data, err := os.ReadFile(active.PolicyPath())
		if err != nil {
			return nil, fmt.Errorf("read signer policy: %w", err)
		}
		return []policy.StoredDocument{{Bytes: data}}, nil
	case noderole.RoleCosigner:
		entries, err := os.ReadDir(active.CosignerPoliciesDir())
		if err != nil {
			return nil, fmt.Errorf("read cosigner policies: %w", err)
		}
		var docs []policy.StoredDocument
		for _, entry := range entries {
			key, ok := strings.CutSuffix(entry.Name(), ".json")
			if !ok {
				continue
			}
			if err := storepaths.ValidateWitnessKeyIDComponent(key); err != nil {
				return nil, fmt.Errorf("cosigner policies contain unsupported entry %q", entry.Name())
			}
			data, err := os.ReadFile(active.CosignerPolicyPath(key))
			if err != nil {
				return nil, err
			}
			docs = append(docs, policy.StoredDocument{Key: key, Bytes: data})
		}
		return docs, nil
	default:
		return nil, fmt.Errorf("unsupported node role %q", role)
	}
}

func policyDocumentPath(active storepaths.GenPaths, key string) string {
	if key == "" {
		return active.PolicyPath()
	}
	return active.CosignerPolicyPath(key)
}

func readStore() (storepaths.GenPaths, *crypto.Keyring, error) {
	fmt.Fprint(os.Stderr, "Enter store passphrase: ")
	passphrase, err := readPassword()
	if err != nil {
		return storepaths.GenPaths{}, nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ZeroBytes(passphrase)
	fmt.Fprintln(os.Stderr)

	active, kr, err := genstore.ResolveStoreRoot(keystorePaths(), passphrase)
	if err != nil {
		return storepaths.GenPaths{}, nil, codedError{code: protocol.ErrCodeInvalidPassphrase, message: fmt.Sprintf("store root verification failed: %v", err)}
	}
	return active, kr, nil
}
