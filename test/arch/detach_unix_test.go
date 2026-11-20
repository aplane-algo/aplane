// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build unix

package arch_test

import (
	"os/exec"
	"syscall"
)

// detachFromTerminal starts cmd in a new session, so it has no controlling
// terminal and cannot open /dev/tty.
func detachFromTerminal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
