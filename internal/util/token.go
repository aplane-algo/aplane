// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

const (
	// TokenLength is the number of random bytes in a token (32 bytes = 256 bits)
	TokenLength = 32

	// aPlaneTokenFile is the token file name for both server and client
	aPlaneTokenFile = "aplane.token"
)

// GetaPlaneTokenPath returns the path to the aPlane token file for an identity.
// Token is stored in the identity-scoped user directory: store/users/<identityID>/aplane.token
// This places the token alongside the keys directory it grants access to.
func GetaPlaneTokenPath(identityID string) string {
	return filepath.Join(utilkeys.UserDir(identityID), aPlaneTokenFile)
}

// GetApshellTokenPath returns the path to the client token file.
// Uses GetClientDataDir resolution: -d flag > APCLIENT_DATA > ~/.aplane
func GetApshellTokenPath() (string, error) {
	dataDir := GetClientDataDir("")
	if dataDir == "" {
		return "", fmt.Errorf("could not determine data directory")
	}
	return filepath.Join(dataDir, aPlaneTokenFile), nil
}

// GenerateToken generates a cryptographically secure random token
func GenerateToken() (string, error) {
	bytes := make([]byte, TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// ReadToken reads a token from a file
// Returns empty string if file doesn't exist (not an error)
// Warns to stderr if file permissions are more permissive than 0600
func ReadToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read token file: %w", err)
	}

	// Check for overly permissive file permissions (group or other access)
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %s has mode %04o, should be 0600 — run: chmod 600 %s\n", path, perm, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read token file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteToken writes a token to a file with secure permissions (0600)
func WriteToken(path, token string) error {
	// Write with restrictive permissions
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}
	return nil
}

// LoadaPlaneToken loads the server token for an identity, generating one if it doesn't exist.
// The token is stored in the identity-scoped keys directory alongside the keys.
func LoadaPlaneToken(identityID string) (string, error) {
	path := GetaPlaneTokenPath(identityID)

	token, err := ReadToken(path)
	if err != nil {
		return "", err
	}

	// If token exists, return it
	if token != "" {
		return token, nil
	}

	// Generate new token
	token, err = GenerateToken()
	if err != nil {
		return "", err
	}

	// Ensure directory exists (keystore/users/default/)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return "", fmt.Errorf("failed to create token directory: %w", err)
	}

	// Save it
	if err := WriteToken(path, token); err != nil {
		return "", err
	}

	fmt.Printf("✓ Generated new API token: %s\n", path)
	fmt.Printf("  Copy this token to your client data directory (~/.aplane or $APCLIENT_DATA)\n")

	return token, nil
}

// LoadApshellToken loads the client token
// Returns empty string if not configured (caller should handle)
func LoadApshellToken() (string, error) {
	path, err := GetApshellTokenPath()
	if err != nil {
		return "", err
	}
	return ReadToken(path)
}

// ValidateToken compares two tokens in constant time to prevent timing attacks
func ValidateToken(provided, expected string) bool {
	if provided == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}
