// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/termsafe"
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

// consoleOf returns c, or stdout when c is nil, as a terminalSafeConsole.
// Every line the signer prints goes through here.
func consoleOf(c Console) Console {
	switch c := c.(type) {
	case nil:
		return terminalSafeConsole{stdConsole{}}
	case terminalSafeConsole:
		return c
	default:
		return terminalSafeConsole{c}
	}
}

// terminalSafeConsole escapes what it prints with termsafe.Lines. Console
// text quotes what a client chose (a transaction type, and the policy rule ID
// and message built from it), and the signer's stdout is an operator's
// terminal (apconsole shows it in a pane): a control sequence printed as is
// would act on that terminal. Lines keeps newlines, so a value printed
// within one line is escaped with termsafe.Line where it is printed.
type terminalSafeConsole struct{ Console }

func (c terminalSafeConsole) Printf(format string, args ...any) {
	c.Console.Printf("%s", termsafe.Lines(fmt.Sprintf(format, args...)))
}

func (c terminalSafeConsole) Println(args ...any) {
	c.Console.Printf("%s", termsafe.Lines(fmt.Sprintln(args...)))
}
