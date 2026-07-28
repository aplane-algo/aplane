// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"fmt"
	"io"
)

// SourceSettingsSnapshot is the non-secret runtime context captured by a new
// managed backup and recorded inside the sealed manifest. UserAutoApprove is
// required for signer sources and omitted for sentry sources.
// GenesisHashMappings contains custom mappings only.
type SourceSettingsSnapshot struct {
	UserAutoApprove     *bool
	GenesisHashMappings map[string]string
}

// requireJSONEOF rejects trailing data after a decoded JSON document.
func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse trailing data: %w", err)
	}
	return fmt.Errorf("trailing JSON value")
}
