// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepaths

import (
	"fmt"
	"path/filepath"
	"regexp"
)

const (
	// StagesDirName holds rotating accounts' stage address tables. It sits
	// beside keys/ under the product directory, not inside a generation, so
	// mints, restores and rollbacks never copy or rewind it, and the key
	// scanner and generation validation never see it. The tables are caches
	// derived from each key's seed; nothing refuses if one is missing.
	StagesDirName = "stages"

	// StageTableFileSuffix names one account's stage address table.
	StageTableFileSuffix = ".stages"
)

// stageSelectorPattern accepts the base32 Algorand address that selects a
// rotating account's key file.
var stageSelectorPattern = regexp.MustCompile(`^[A-Z2-7]{58}$`)

// ValidateStageSelector reports whether selector is usable as a stage table
// file-name component.
func ValidateStageSelector(selector string) error {
	if !stageSelectorPattern.MatchString(selector) {
		return fmt.Errorf("invalid stage table selector %q", selector)
	}
	return nil
}

// StagesDir is identities/default/stages.
func (p Paths) StagesDir() string {
	return filepath.Join(p.ProductDir(), StagesDirName)
}

// StageTablePath is the stage address table of the rotating account with
// selector.
func (p Paths) StageTablePath(selector string) string {
	if err := ValidateStageSelector(selector); err != nil {
		panic(err.Error())
	}
	return filepath.Join(p.StagesDir(), selector+StageTableFileSuffix)
}
