// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/backup"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/noderole"
)

// restoreKey rebuilds one backup entry into the test store's active
// generation, as a rebuild does: keysDir holds the entry's .apb file, which
// is sealed into an archive under exportPassphrase first.
func restoreKey(keysDir, address string, kr *crypto.Keyring, exportPassphrase []byte) (string, error) {
	root, err := os.MkdirTemp("", "apstore-restore-key-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := os.MkdirAll(filepath.Join(root, "apb"), 0o700); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(keysDir, address+".apb"))
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(root, "apb", address+".apb"), data, 0o600); err != nil {
		return "", err
	}
	role := noderole.DefaultRole()
	if err := backup.WriteSealedManifest(root, role, time.Unix(1_700_000_000, 0), exportPassphrase, nil); err != nil {
		return "", err
	}
	set, err := backup.LoadRebuildSet(root, []string{address}, exportPassphrase, role)
	if err != nil {
		return "", err
	}
	defer set.ZeroSecrets()
	paths, err := genstoretest.BindDefault(keystorePaths())
	if err != nil {
		return "", err
	}
	active, err := genstore.Resolve(paths)
	if err != nil {
		return "", err
	}
	if err := backup.ApplyRebuildSet(active, role, set, kr); err != nil {
		return "", err
	}
	return set.Entries[0].KeyType(), nil
}
