// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"os"
)

// GetBytecode returns the lsig bytecode, either from memory or from the associated file.
func (lsig *LSigConfig) GetBytecode() ([]byte, error) {
	if lsig == nil {
		return nil, fmt.Errorf("lsig config is nil")
	}

	if len(lsig.Bytecode) > 0 {
		return lsig.Bytecode, nil
	}

	if lsig.LSigFile == "" {
		return nil, fmt.Errorf("no bytecode or file available for lsig")
	}

	data, err := os.ReadFile(lsig.LSigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read lsig file %s: %w", lsig.LSigFile, err)
	}
	return data, nil
}
