// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package tokenfile manages on-disk signer and apshell token files.
package tokenfile

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const (
	// TokenLength is the number of random bytes in a token (32 bytes = 256 bits).
	TokenLength = 32

	// APlaneTokenFile is the token file name for both server and client.
	APlaneTokenFile = "aplane.token"
)

// GetAPlaneTokenPathForRoot returns the path to the signer token for an
// explicit keystore root.
func GetAPlaneTokenPathForRoot(root, identityID string) string {
	return filepath.Join(storepaths.NewPaths(root).IdentityDir(identityID), APlaneTokenFile)
}

// GetApshellTokenPathForDataDir returns the path to the client token file for
// an explicit data dir.
func GetApshellTokenPathForDataDir(dataDir string) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("could not determine data directory")
	}
	return filepath.Join(dataDir, APlaneTokenFile), nil
}

// GenerateToken generates a cryptographically secure random token.
func GenerateToken() (string, error) {
	bytes := make([]byte, TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// ReadToken reads a token from a file. Returns an empty string if the file does
// not exist. Group/world-accessible token files are rejected because the token
// is a bearer credential.
func ReadToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read token file: %w", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("%s has insecure mode %04o, should be 0600 — run: chmod 600 %s", path, perm, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read token file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteToken writes a token to a file with owner-only permissions (0600).
func WriteToken(path, token string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp token file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write([]byte(token + "\n")); err != nil {
		return fmt.Errorf("failed to write token data: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("failed to set token permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp token file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to replace token file: %w", err)
	}
	cleanup = false
	return nil
}

func writeTokenIfAbsent(path, token string) (bool, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("failed to create temp token file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write([]byte(token + "\n")); err != nil {
		return false, fmt.Errorf("failed to write token data: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return false, fmt.Errorf("failed to set token permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		closed = true
		return false, fmt.Errorf("failed to close temp token file: %w", err)
	}
	closed = true

	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to create token file: %w", err)
	}
	return true, nil
}

// LoadAPlaneToken loads the server token for an identity, generating one if it
// does not exist.
func LoadAPlaneToken(root, identityID string) (string, error) {
	path := GetAPlaneTokenPathForRoot(root, identityID)

	token, err := ReadToken(path)
	if err != nil {
		return "", err
	}
	if token != "" {
		return token, nil
	}

	token, err = GenerateToken()
	if err != nil {
		return "", err
	}

	if err := fsutil.MkdirAll(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("failed to create token directory: %w", err)
	}
	created, err := writeTokenIfAbsent(path, token)
	if err != nil {
		return "", err
	}
	if !created {
		return ReadToken(path)
	}

	fmt.Printf("✓ Generated new API token: %s\n", path)
	fmt.Printf("  Copy this token to your client data directory ($APCLIENT_DATA)\n")

	return token, nil
}

// LoadApshellTokenFromDataDir loads the client token from an explicit data dir.
func LoadApshellTokenFromDataDir(dataDir string) (string, error) {
	path, err := GetApshellTokenPathForDataDir(dataDir)
	if err != nil {
		return "", err
	}
	return ReadToken(path)
}

// ValidateToken compares two tokens in constant time to prevent timing attacks.
func ValidateToken(provided, expected string) bool {
	if provided == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
