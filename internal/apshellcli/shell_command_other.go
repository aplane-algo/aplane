// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !unix

package apshellcli

import "os/exec"

// runInOwnProcessGroup leaves cmd as it is: without process groups, a cancel
// kills the shell alone.
func runInOwnProcessGroup(*exec.Cmd) {}
