// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func consoleNodeRole(paths storepaths.Paths) (noderole.Role, string) {
	doc, _, err := noderole.Load(paths)
	if err == nil {
		return doc.Role, ""
	}
	return noderole.DefaultRole(), fmt.Sprintf("could not read node role; assuming signer: %v", err)
}

func shellPaneEnabledForNodeRole(role noderole.Role) bool {
	return role != noderole.RoleAttestor
}

func attestorShellDisabledLines(notices []string) []string {
	lines := consoleStartupNoticeLines(notices)
	lines = append(lines,
		"[config] shell pane disabled on attestor nodes",
		"Use F1 Admin and press p to edit attestation policy.",
	)
	return lines
}
