// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

const maxSentryPublicEnvelopeBytes = 64 * 1024

// ReadSentryPublicEnvelope reads a bounded public witness envelope from a
// regular file, or from stdin when path is "-".
func ReadSentryPublicEnvelope(path string, stdin io.Reader) ([]byte, error) {
	if path != "-" {
		data, _, err := fsutil.ReadRegularFileLimited(path, maxSentryPublicEnvelopeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read sentry public key export: %w", err)
		}
		return data, nil
	}
	if stdin == nil {
		return nil, fmt.Errorf("cannot read sentry public key export from stdin: stdin is unavailable")
	}
	limited := io.LimitReader(stdin, maxSentryPublicEnvelopeBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read sentry public key export from stdin: %w", err)
	}
	if len(data) > maxSentryPublicEnvelopeBytes {
		return nil, fmt.Errorf("sentry public key export from stdin exceeds %d bytes", maxSentryPublicEnvelopeBytes)
	}
	return data, nil
}

// WriteSentryPublicEnvelope durably publishes a public witness envelope to an
// owner-private regular file without following a destination symlink.
func WriteSentryPublicEnvelope(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("output path is required")
	}
	if err := fsutil.WriteFileDurableWithProfile(path, data, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("failed to write public key envelope: %w", err)
	}
	return nil
}

// CompactWitnessKeyID formats a Witness Key ID for a non-trust-bearing row.
func CompactWitnessKeyID(id string) string {
	const edge = 10
	if len(id) <= edge*2+3 {
		return id
	}
	return id[:edge] + "..." + id[len(id)-edge:]
}
