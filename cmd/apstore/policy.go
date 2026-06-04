// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
)

type policyCommandDocument struct {
	name      string
	path      string
	sidecar   string
	loadCheck func() (*policy.StoredConfig, error)
	verify    func(masterKey []byte) (*policy.StoredConfig, error)
	apply     func(*policy.StoredConfig) (*policy.Config, error)
	sign      func(masterKey []byte, signedAt time.Time) error
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
	for _, doc := range policyCommandDocuments() {
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
	masterKey, err := readPolicyMasterKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey)

	for _, doc := range policyCommandDocuments() {
		stored, err := doc.verify(masterKey)
		if err != nil {
			return fmt.Errorf("%s integrity verification failed: %w", doc.name, err)
		}
		if _, err := doc.apply(stored); err != nil {
			return fmt.Errorf("%s config invalid: %w", doc.name, err)
		}
		logInfof("%s integrity verified: %s", doc.name, doc.path)
	}
	return nil
}

func cmdPolicySign() error {
	docs := policyCommandDocuments()
	for _, doc := range docs {
		if _, err := doc.loadCheck(); err != nil {
			return err
		}
	}
	masterKey, err := readPolicyMasterKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey)

	now := time.Now()
	for _, doc := range docs {
		if err := doc.sign(masterKey, now); err != nil {
			return fmt.Errorf("failed to sign %s integrity sidecar: %w", doc.name, err)
		}
		if _, err := doc.verify(masterKey); err != nil {
			return fmt.Errorf("%s sidecar written but verification failed: %w", doc.name, err)
		}
		logInfof("%s sidecar signed: %s", doc.name, doc.sidecar)
	}
	return nil
}

func policyCommandDocuments() []policyCommandDocument {
	identityID := productIdentityID()
	policyPath := policy.PolicyPath(dataDirectory, identityID)
	attestationPath := policy.AttestationPath(dataDirectory, identityID)
	return []policyCommandDocument{
		{
			name:    "policy.yaml",
			path:    policyPath,
			sidecar: policy.PolicyIntegritySidecarPath(policyPath),
			loadCheck: func() (*policy.StoredConfig, error) {
				return loadPolicyDocumentForCheck("policy.yaml", policyPath, policy.ParseStoredConfig, func(stored *policy.StoredConfig) (*policy.Config, error) {
					return policyruntime.ApplyStoredConfig(dataDirectory, &config, stored)
				})
			},
			verify: func(masterKey []byte) (*policy.StoredConfig, error) {
				return policy.LoadVerifiedStoredConfigWithMasterKey(dataDirectory, identityID, masterKey)
			},
			apply: func(stored *policy.StoredConfig) (*policy.Config, error) {
				return policyruntime.ApplyStoredConfig(dataDirectory, &config, stored)
			},
			sign: func(masterKey []byte, signedAt time.Time) error {
				return policy.SignPolicyFileIntegrityWithMasterKey(dataDirectory, identityID, masterKey, signedAt)
			},
		},
		{
			name:    "attestation.yaml",
			path:    attestationPath,
			sidecar: policy.PolicyIntegritySidecarPath(attestationPath),
			loadCheck: func() (*policy.StoredConfig, error) {
				return loadPolicyDocumentForCheck("attestation.yaml", attestationPath, policy.ParseStoredAttestationConfig, func(stored *policy.StoredConfig) (*policy.Config, error) {
					return policyruntime.ApplyAttestationStoredConfig(dataDirectory, &config, stored)
				})
			},
			verify: func(masterKey []byte) (*policy.StoredConfig, error) {
				return policy.LoadVerifiedAttestationConfigWithMasterKey(dataDirectory, identityID, masterKey)
			},
			apply: func(stored *policy.StoredConfig) (*policy.Config, error) {
				return policyruntime.ApplyAttestationStoredConfig(dataDirectory, &config, stored)
			},
			sign: func(masterKey []byte, signedAt time.Time) error {
				return policy.SignAttestationFileIntegrityWithMasterKey(dataDirectory, identityID, masterKey, signedAt)
			},
		},
	}
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

func readPolicyMasterKey() ([]byte, error) {
	fmt.Print("Enter store passphrase: ")
	passphrase, err := readPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ZeroBytes(passphrase)
	fmt.Println()

	meta, err := crypto.LoadKeystoreMetadata(keystorePaths().KeystoreMetadataDir(productIdentityID()))
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	if err != nil {
		return nil, fmt.Errorf("passphrase verification failed: %w", err)
	}
	return masterKey, nil
}
