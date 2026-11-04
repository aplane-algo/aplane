// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/crypto"
)

var (
	// ErrNoIdentityKey means the identity file doesn't exist yet.
	ErrNoIdentityKey = errors.New("no SSH identity key")
	// ErrIdentityKeyEncrypted means the identity file needs a passphrase, which
	// the client neither asks for nor stores.
	ErrIdentityKeyEncrypted = errors.New("SSH identity key is encrypted")
)

// IdentityPublicKey is the public half of a client's SSH identity.
type IdentityPublicKey struct {
	// AuthorizedKey is one OpenSSH public-key line, with no trailing newline.
	AuthorizedKey string
	Fingerprint   string
}

// ReadIdentityPublicKey derives the public key of an existing identity file. It
// only reads: unlike connecting, it never creates a missing key, and a failure
// leaves the file as it was.
func ReadIdentityPublicKey(identityFile string) (IdentityPublicKey, error) {
	keyData, err := os.ReadFile(expandUserPath(identityFile))
	if err != nil {
		if os.IsNotExist(err) {
			return IdentityPublicKey{}, fmt.Errorf("%w: %s", ErrNoIdentityKey, identityFile)
		}
		return IdentityPublicKey{}, fmt.Errorf("failed to read SSH identity file: %w", err)
	}
	defer crypto.ZeroBytes(keyData)

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return IdentityPublicKey{}, fmt.Errorf("%w: %s", ErrIdentityKeyEncrypted, identityFile)
		}
		return IdentityPublicKey{}, fmt.Errorf("failed to parse SSH identity file %s: %w", identityFile, err)
	}
	publicKey := signer.PublicKey()
	return IdentityPublicKey{
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))),
		Fingerprint:   ssh.FingerprintSHA256(publicKey),
	}, nil
}
