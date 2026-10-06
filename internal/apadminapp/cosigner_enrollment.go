// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// MaxCosignerPublicEnvelopeBytes bounds a cosigner public key file before it
// is decoded.
const MaxCosignerPublicEnvelopeBytes = 64 * 1024

const maxCosignerPublicEnvelopeBytes = MaxCosignerPublicEnvelopeBytes

// ReadCosignerPublicEnvelope reads a bounded public witness envelope from a
// regular file, or from stdin when path is "-".
func ReadCosignerPublicEnvelope(path string, stdin io.Reader) ([]byte, error) {
	if path != "-" {
		data, _, err := fsutil.ReadRegularFileLimited(path, maxCosignerPublicEnvelopeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read cosigner public key export: %w", err)
		}
		return data, nil
	}
	if stdin == nil {
		return nil, fmt.Errorf("cannot read cosigner public key export from stdin: stdin is unavailable")
	}
	limited := io.LimitReader(stdin, maxCosignerPublicEnvelopeBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read cosigner public key export from stdin: %w", err)
	}
	if len(data) > maxCosignerPublicEnvelopeBytes {
		return nil, fmt.Errorf("cosigner public key export from stdin exceeds %d bytes", maxCosignerPublicEnvelopeBytes)
	}
	return data, nil
}

// WriteCosignerPublicEnvelope durably publishes a public witness envelope to an
// owner-private regular file without following a destination symlink.
func WriteCosignerPublicEnvelope(path string, data []byte) error {
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
