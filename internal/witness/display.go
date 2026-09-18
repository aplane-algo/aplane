// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package witness

import "strings"

// GroupedID formats a Witness Key ID in four-character groups for manual
// comparison. It does not normalize or validate the value.
func GroupedID(id string) string {
	if id == "" {
		return ""
	}
	groups := make([]string, 0, (len(id)+3)/4)
	for len(id) > 4 {
		groups = append(groups, id[:4])
		id = id[4:]
	}
	groups = append(groups, id)
	return strings.Join(groups, " ")
}
