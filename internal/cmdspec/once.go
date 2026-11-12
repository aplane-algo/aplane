// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import "fmt"

// SeenOptions records which single-valued options a command has been given,
// so a second value is refused rather than silently replacing the first. An
// option is recorded under one name however it is spelled: `--pay 5` and
// `pay=5` are both "pay".
type SeenOptions map[string]bool

// Once records the option name, and refuses it if it was given before.
func (s SeenOptions) Once(name string) error {
	if s[name] {
		return fmt.Errorf("%s given more than once", name)
	}
	s[name] = true
	return nil
}
