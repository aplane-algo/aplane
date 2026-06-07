// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeinit

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

type Options struct {
	DataDir    string
	Paths      storepaths.Paths
	IdentityID string
	Role       noderole.Role
	Logf       func(format string, args ...any)
}

type Result struct {
	MetadataDir string
}

func Initialize(passphrase []byte, opts Options) (Result, error) {
	var result Result
	if len(passphrase) == 0 {
		return result, fmt.Errorf("passphrase cannot be empty")
	}
	if opts.DataDir == "" {
		return result, fmt.Errorf("data directory is required")
	}
	if opts.IdentityID == "" {
		return result, fmt.Errorf("identity ID is required")
	}
	role := opts.Role
	if role == "" {
		role = noderole.DefaultRole()
	}
	if _, err := noderole.ParseRole(string(role)); err != nil {
		return result, err
	}

	if err := requireLocalOwnerOrRoot(opts.DataDir); err != nil {
		return result, err
	}

	metadataDir := opts.Paths.KeystoreMetadataDir(opts.IdentityID)
	result.MetadataDir = metadataDir
	if crypto.KeystoreMetadataExistsIn(metadataDir) {
		return result, fmt.Errorf("keystore already initialized (control file exists in %s)", metadataDir)
	}
	if HasPartialState(opts.Paths, opts.IdentityID) {
		return result, fmt.Errorf("keystore appears partially initialized in %s; clean up the existing identity directory before re-running initialize", opts.Paths.IdentityDir(opts.IdentityID))
	}

	logf(opts.Logf, "keystore directory: %s", metadataDir)
	if err := fsutil.MkdirAll(metadataDir); err != nil {
		return result, fmt.Errorf("failed to create user directory: %w", err)
	}

	createdNodeRole := false
	success := false
	defer func() {
		if !success && createdNodeRole {
			_ = os.Remove(opts.Paths.NodeRolePath())
		}
	}()

	_, masterKey, err := crypto.CreateKeystoreMetadata(metadataDir, passphrase)
	if err != nil {
		return result, fmt.Errorf("failed to create keystore metadata: %w", err)
	}
	roleBytes, _, err := noderole.SaveInitial(opts.Paths, role, time.Now())
	if err != nil {
		crypto.ZeroBytes(masterKey)
		return result, fmt.Errorf("failed to create node role: %w", err)
	}
	createdNodeRole = true
	if err := noderole.SaveIdentitySidecarWithMasterKey(opts.Paths, opts.IdentityID, roleBytes, masterKey, time.Now()); err != nil {
		crypto.ZeroBytes(masterKey)
		return result, fmt.Errorf("failed to create node role integrity sidecar: %w", err)
	}
	var policyErr error
	if role == noderole.RoleSentry {
		policyErr = policy.SaveStoredAttestationConfigWithMasterKey(opts.DataDir, opts.IdentityID, &policy.StoredConfig{}, masterKey, time.Now())
	} else {
		policyErr = policy.SaveStoredConfigWithMasterKey(opts.DataDir, opts.IdentityID, &policy.StoredConfig{}, masterKey, time.Now())
	}
	if policyErr != nil {
		crypto.ZeroBytes(masterKey)
		return result, fmt.Errorf("failed to create policy integrity baseline: %w", policyErr)
	}
	crypto.ZeroBytes(masterKey)

	if err := fsutil.MkdirAll(opts.Paths.KeysDir(opts.IdentityID)); err != nil {
		return result, fmt.Errorf("failed to create keys directory: %w", err)
	}

	if _, err := tokenfile.LoadAPlaneToken(opts.Paths.Root(), opts.IdentityID); err != nil {
		return result, fmt.Errorf("failed to generate API token: %w", err)
	}

	chownIdentitiesTreeToDataDirOwner(opts.DataDir, opts.Paths)
	success = true
	return result, nil
}

func HasPartialState(paths storepaths.Paths, identityID string) bool {
	identityDir := paths.IdentityDir(identityID)
	entries, err := os.ReadDir(identityDir)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if entry.Name() == ".keystore" {
			return false
		}
		if entry.Name() == "aplane.token" {
			continue
		}
		return true
	}
	return false
}

func requireLocalOwnerOrRoot(dataDir string) error {
	if os.Getuid() == 0 {
		return nil
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		return fmt.Errorf("cannot stat data directory %s: %w", dataDir, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("local signer data directory %s is not owned by the current user; fix ownership or use a systemd-managed install", dataDir)
	}
	return nil
}

func chownIdentitiesTreeToDataDirOwner(dataDir string, paths storepaths.Paths) {
	info, err := os.Stat(dataDir)
	if err != nil {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	uid := int(stat.Uid)
	gid := int(stat.Gid)
	usersDir := filepath.Join(paths.Root(), "identities")
	_ = filepath.Walk(usersDir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

func logf(log func(format string, args ...any), format string, args ...any) {
	if log != nil {
		log(format, args...)
	}
}
