// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

//go:build !unix

package arch_test

import "os/exec"

func detachFromTerminal(*exec.Cmd) {}
