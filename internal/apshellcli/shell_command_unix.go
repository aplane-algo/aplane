// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build unix

package apshellcli

import (
	"os/exec"
	"syscall"
)

// runInOwnProcessGroup starts cmd in a process group of its own, and makes
// its cancel kill that whole group: what the shell started, not the shell
// alone.
func runInOwnProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// The group's ID is the shell's PID, as Setpgid made it.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
