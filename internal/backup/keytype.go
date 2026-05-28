// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

func validateBackupKeyType(keyType string) error {
	if err := storepaths.ValidateKeyTypeComponent(keyType); err != nil {
		return fmt.Errorf("invalid key_type %q: %w", keyType, err)
	}
	return nil
}

func isBackupTemplateKeyType(keyType string) bool {
	firstDot := strings.IndexByte(keyType, '.')
	lastDot := strings.LastIndexByte(keyType, '.')
	if firstDot <= 0 || lastDot <= firstDot+1 || lastDot == len(keyType)-1 {
		return false
	}
	versionSegment := keyType[lastDot+1:]
	if len(versionSegment) < 2 || versionSegment[0] != 'v' {
		return false
	}
	version, err := strconv.Atoi(versionSegment[1:])
	return err == nil && version >= 1
}
