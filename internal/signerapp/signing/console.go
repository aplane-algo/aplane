// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"os"
)

type Console interface {
	Printf(format string, args ...any)
	Println(args ...any)
	Sync()
}

type stdConsole struct{}

func (stdConsole) Printf(format string, args ...any) { fmt.Printf(format, args...) }
func (stdConsole) Println(args ...any)               { fmt.Println(args...) }
func (stdConsole) Sync()                             { _ = os.Stdout.Sync() }

func consoleOf(c Console) Console {
	if c != nil {
		return c
	}
	return stdConsole{}
}
