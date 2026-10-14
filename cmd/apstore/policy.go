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
// reports documents for keys the node does not hold.
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
	docs, err := storedPolicyDocuments(active)
	if err != nil {
		return err
	}
	np, err := policyruntime.Compile(role, dataDirectory, &config, docs)
	if err != nil {
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
	held, err := policyapply.HeldPolicyKeysInGeneration(role, active)
	if err != nil {
		return err
	}
	for _, warning := range policyapply.CoverageWarnings(policyapply.KeyStatus(held, np)) {
		logWarnf("%s: %s", warning.Key, warning.Message)
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
	if err := policy.ResignDefault(active, role, kr, now); err != nil {
		return fmt.Errorf("sign policy sidecars: %w", err)
	}
	if err := policy.ResignKeyPolicies(active, role, kr, now); err != nil {
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

// storedPolicyDocuments reads the default and every per-key document
// without verifying their sidecars.
func storedPolicyDocuments(active storepaths.GenPaths) ([]policy.StoredDocument, error) {
	data, err := os.ReadFile(active.DefaultPolicyPath())
	if err != nil {
		return nil, fmt.Errorf("read default policy: %w", err)
	}
	docs := []policy.StoredDocument{{Key: policy.DefaultKey, Bytes: data}}
	entries, err := os.ReadDir(active.PoliciesDir())
	if err != nil {
		return nil, fmt.Errorf("read key policies: %w", err)
	}
	for _, entry := range entries {
		key, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok {
			continue
		}
		if err := storepaths.ValidatePolicySelector(key); err != nil {
			return nil, fmt.Errorf("key policies contain unsupported entry %q", entry.Name())
		}
		data, err := os.ReadFile(active.PolicyPath(key))
		if err != nil {
			return nil, err
		}
		docs = append(docs, policy.StoredDocument{Key: key, Bytes: data})
	}
	return docs, nil
}

func policyDocumentPath(active storepaths.GenPaths, key string) string {
	if key == policy.DefaultKey {
		return active.DefaultPolicyPath()
	}
	return active.PolicyPath(key)
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
