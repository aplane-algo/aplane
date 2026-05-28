// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
	"regexp"
)

const maxNetworkIDLength = 64

var networkIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// ValidateNetworkID validates an APlane-local network context token.
func ValidateNetworkID(id string) error {
	if id == "" {
		return fmt.Errorf("network id is required")
	}
	if len(id) > maxNetworkIDLength {
		return fmt.Errorf("network id %q is too long (max %d characters)", id, maxNetworkIDLength)
	}
	if !networkIDPattern.MatchString(id) {
		return fmt.Errorf("invalid network id %q (use lowercase letters, digits, '_' or '-', starting with a letter or digit)", id)
	}
	return nil
}
