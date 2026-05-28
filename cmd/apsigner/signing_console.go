// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"os"
)

type signerConsole struct{}

func (signerConsole) Printf(format string, args ...any) { fmt.Printf(format, args...) }
func (signerConsole) Println(args ...any)               { fmt.Println(args...) }
func (signerConsole) Sync()                             { _ = os.Stdout.Sync() }
