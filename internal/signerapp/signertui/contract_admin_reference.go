// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/witness"
)

const maxContractAdminReferenceBytes = 16 * 1024

func isContractAdminReferenceParam(param lsigprovider.ParameterDef) bool {
	return param.Name == boundedmeta.AdminPublicKeyParameter && param.Type == "bytes"
}

// loadContractAdminPublicKey converts a local public reference into the hex
// parameter expected by the signer. The private .wit artifact is never read.
func loadContractAdminPublicKey(inputPath string) (string, error) {
	path := strings.TrimSpace(inputPath)
	if path == "" {
		return "", fmt.Errorf("select a contract-admin .wit.json file")
	}
	if !strings.HasSuffix(path, ".wit.json") {
		return "", fmt.Errorf("contract-admin reference must be a .wit.json file")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	data, _, err := fsutil.ReadRegularFileLimited(path, maxContractAdminReferenceBytes)
	if err != nil {
		return "", fmt.Errorf("read contract-admin reference %q: %w", path, err)
	}
	reference, err := witness.ParsePublicReference(data)
	if err != nil {
		return "", fmt.Errorf("invalid contract-admin reference %q: %w", path, err)
	}
	if reference.KeyType != witness.Falcon1024V1 {
		return "", fmt.Errorf("contract-admin reference %q has unsupported key type %q", path, reference.KeyType)
	}
	return reference.PublicKeyHex, nil
}
