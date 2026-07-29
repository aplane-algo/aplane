// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type policyCommandDocument struct {
	name      string
	path      string
	sidecar   string
	loadCheck func() (*policy.StoredConfig, error)
	verify    func(kr *crypto.Keyring) (*policy.StoredConfig, error)
	apply     func(*policy.StoredConfig) (*policy.Config, error)
	sign      func(kr *crypto.Keyring, signedAt time.Time) error
}

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

func cmdPolicyCheck() error {
	docs, err := policyCommandDocuments()
	if err != nil {
		return err
	}
	for _, doc := range docs {
		if _, err := doc.loadCheck(); err != nil {
			return err
		}
		sidecarBytes, err := os.ReadFile(doc.sidecar)
		if os.IsNotExist(err) {
			logWarnf("%s sidecar missing: %s", doc.name, doc.sidecar)
			logWarnf("run apstore policy sign after reviewing direct policy edits")
		} else if err != nil {
			return fmt.Errorf("failed to read %s sidecar: %w", doc.name, err)
		} else if _, err := policy.ParsePolicyIntegritySidecar(sidecarBytes); err != nil {
			return fmt.Errorf("failed to parse %s sidecar: %w", doc.name, err)
		} else {
			logInfof("%s sidecar shape OK: %s", doc.name, doc.sidecar)
		}
		logInfof("%s syntax OK: %s", doc.name, doc.path)
	}
	return nil
}

func cmdPolicyVerify() error {
	docs, err := policyCommandDocuments()
	if err != nil {
		return err
	}
	kr, err := readPolicyKeyring()
	if err != nil {
		return err
	}
	defer kr.Zero()

	for _, doc := range docs {
		stored, err := doc.verify(kr)
		if err != nil {
			return codedError{code: policyIntegrityFailedCode, message: fmt.Sprintf("%s integrity verification failed: %v", doc.name, err)}
		}
		if _, err := doc.apply(stored); err != nil {
			return fmt.Errorf("%s config invalid: %w", doc.name, err)
		}
		logInfof("%s integrity verified: %s", doc.name, doc.path)
	}
	return nil
}

func cmdPolicySign() error {
	docs, err := policyCommandDocuments()
	if err != nil {
		return err
	}
	for _, doc := range docs {
		if _, err := doc.loadCheck(); err != nil {
			return err
		}
	}
	kr, err := readPolicyKeyring()
	if err != nil {
		return err
	}
	defer kr.Zero()

	now := time.Now()
	for _, doc := range docs {
		if err := doc.sign(kr, now); err != nil {
			return fmt.Errorf("failed to sign %s integrity sidecar: %w", doc.name, err)
		}
		if _, err := doc.verify(kr); err != nil {
			return codedError{code: policyIntegrityFailedCode, message: fmt.Sprintf("%s sidecar written but verification failed: %v", doc.name, err)}
		}
		logInfof("%s sidecar signed: %s", doc.name, doc.sidecar)
	}
	return nil
}

func policyCommandDocuments() ([]policyCommandDocument, error) {
	identityID := productIdentityID()
	policyPath := policy.PolicyPath(dataDirectory, identityID)
	nodeDoc, _, err := noderole.Load(storepaths.NewPaths(dataDirectory))
	if err != nil {
		return nil, fmt.Errorf("failed to load node role: %w", err)
	}
	doc := policyCommandDocument{
		name:    "policy.yaml",
		path:    policyPath,
		sidecar: policy.PolicyIntegritySidecarPath(policyPath),
	}
	switch nodeDoc.Role {
	case noderole.RoleSentry:
		doc.loadCheck = func() (*policy.StoredConfig, error) {
			return loadPolicyDocumentForCheck("policy.yaml", policyPath, policy.ParseStoredSentryConfig, func(stored *policy.StoredConfig) (*policy.Config, error) {
				return policyruntime.ApplySentryStoredConfig(dataDirectory, &config, stored)
			})
		}
		doc.verify = func(kr *crypto.Keyring) (*policy.StoredConfig, error) {
			return policy.LoadVerifiedSentryConfigWithKeyring(dataDirectory, identityID, kr)
		}
		doc.apply = func(stored *policy.StoredConfig) (*policy.Config, error) {
			return policyruntime.ApplySentryStoredConfig(dataDirectory, &config, stored)
		}
		doc.sign = func(kr *crypto.Keyring, signedAt time.Time) error {
			return policy.SignSentryFileIntegrityWithKeyring(dataDirectory, identityID, kr, signedAt)
		}
	case noderole.RoleSigner:
		doc.loadCheck = func() (*policy.StoredConfig, error) {
			return loadPolicyDocumentForCheck("policy.yaml", policyPath, policy.ParseStoredConfig, func(stored *policy.StoredConfig) (*policy.Config, error) {
				return policyruntime.ApplyStoredConfig(dataDirectory, &config, stored)
			})
		}
		doc.verify = func(kr *crypto.Keyring) (*policy.StoredConfig, error) {
			return policy.LoadVerifiedStoredConfigWithKeyring(dataDirectory, identityID, kr)
		}
		doc.apply = func(stored *policy.StoredConfig) (*policy.Config, error) {
			return policyruntime.ApplyStoredConfig(dataDirectory, &config, stored)
		}
		doc.sign = func(kr *crypto.Keyring, signedAt time.Time) error {
			return policy.SignPolicyFileIntegrityWithKeyring(dataDirectory, identityID, kr, signedAt)
		}
	default:
		return nil, fmt.Errorf("unsupported node role %q", nodeDoc.Role)
	}
	return []policyCommandDocument{doc}, nil
}

func loadPolicyDocumentForCheck(name, path string, parser func([]byte) (*policy.StoredConfig, error), apply func(*policy.StoredConfig) (*policy.Config, error)) (*policy.StoredConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s file missing: %s", name, path)
		}
		return nil, fmt.Errorf("failed to read %s config: %w", name, err)
	}
	stored, err := parser(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s config: %w", name, err)
	}
	if _, err := apply(stored); err != nil {
		return nil, fmt.Errorf("%s config invalid: %w", name, err)
	}
	return stored, nil
}

func readPolicyKeyring() (*crypto.Keyring, error) {
	return readStoreKeyring()
}

func readStoreKeyring() (*crypto.Keyring, error) {
	fmt.Fprint(os.Stderr, "Enter store passphrase: ")
	passphrase, err := readPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ZeroBytes(passphrase)
	fmt.Fprintln(os.Stderr)

	kr, err := crypto.OpenKeyringStore(keystorePaths().KeystoreMetadataDir(productIdentityID()), passphrase)
	if err != nil {
		return nil, codedError{code: protocol.ErrCodeInvalidPassphrase, message: fmt.Sprintf("passphrase verification failed: %v", err)}
	}
	return kr, nil
}
