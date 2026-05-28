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
	if _, err := loadPolicyForCheck(); err != nil {
		return err
	}
	path := policy.PolicyPath(dataDirectory, productIdentityID())
	sidecarPath := policy.PolicyIntegritySidecarPath(path)
	sidecarBytes, err := os.ReadFile(sidecarPath)
	if os.IsNotExist(err) {
		logWarnf("policy sidecar missing: %s", sidecarPath)
		logWarnf("run apstore policy sign after reviewing direct policy edits")
	} else if err != nil {
		return fmt.Errorf("failed to read policy sidecar: %w", err)
	} else if _, err := policy.ParsePolicyIntegritySidecar(sidecarBytes); err != nil {
		return fmt.Errorf("failed to parse policy sidecar: %w", err)
	} else {
		logInfof("policy sidecar shape OK: %s", sidecarPath)
	}
	logInfof("policy syntax OK: %s", path)
	return nil
}

func cmdPolicyVerify() error {
	masterKey, err := readPolicyMasterKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey)

	stored, err := policy.LoadVerifiedStoredConfigWithMasterKey(dataDirectory, productIdentityID(), masterKey)
	if err != nil {
		return fmt.Errorf("policy integrity verification failed: %w", err)
	}
	if _, err := policyruntime.ApplyStoredConfig(dataDirectory, &config, stored); err != nil {
		return fmt.Errorf("policy config invalid: %w", err)
	}
	logInfof("policy integrity verified: %s", policy.PolicyPath(dataDirectory, productIdentityID()))
	return nil
}

func cmdPolicySign() error {
	if _, err := loadPolicyForCheck(); err != nil {
		return err
	}
	masterKey, err := readPolicyMasterKey()
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(masterKey)

	if err := policy.SignPolicyFileIntegrityWithMasterKey(dataDirectory, productIdentityID(), masterKey, time.Now()); err != nil {
		return fmt.Errorf("failed to sign policy integrity sidecar: %w", err)
	}
	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(dataDirectory, productIdentityID(), masterKey); err != nil {
		return fmt.Errorf("policy sidecar written but verification failed: %w", err)
	}
	logInfof("policy sidecar signed: %s", policy.PolicyIntegritySidecarPath(policy.PolicyPath(dataDirectory, productIdentityID())))
	return nil
}

func loadPolicyForCheck() (*policy.StoredConfig, error) {
	path := policy.PolicyPath(dataDirectory, productIdentityID())
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("policy file missing: %s", path)
		}
		return nil, fmt.Errorf("failed to read policy config: %w", err)
	}
	stored, err := policy.ParseStoredConfig(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy config: %w", err)
	}
	if _, err := policyruntime.ApplyStoredConfig(dataDirectory, &config, stored); err != nil {
		return nil, fmt.Errorf("policy config invalid: %w", err)
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
