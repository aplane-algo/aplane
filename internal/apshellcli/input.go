// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bufio"
	"os"
	"strings"
)

func (r *REPLState) clearInputPrompt() {
	if r.SetPrompt != nil {
		r.SetPrompt("")
	}
}

func (r *REPLState) setTemporaryPrompt(prompt string) func() {
	if r.SetPrompt == nil {
		return func() {}
	}
	r.SetPrompt(prompt)
	return func() {
		if r.App != nil {
			r.SetPrompt(r.promptString())
			return
		}
		r.SetPrompt("")
	}
}

func (r *REPLState) readInteractiveLine() (string, error) {
	if r.LineReaderContext != nil {
		return r.LineReaderContext(r.commandContext())
	}
	if r.LineReader != nil {
		return r.LineReader()
	}

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", nil
	}
	return scanner.Text(), nil
}

func (r *REPLState) hasInteractiveLineReader() bool {
	return r.LineReaderContext != nil || r.LineReader != nil
}

// confirm asks a [y/N] question and reports whether the answer was y or
// yes, in any case. Anything else, an empty answer included, is no.
func (r *REPLState) confirm(prompt string) (bool, error) {
	answer, err := r.readPromptLine(prompt)
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(answer)
	return answer == "y" || answer == "yes", nil
}

// readPromptLine shows prompt and reads one line, trimmed.
func (r *REPLState) readPromptLine(prompt string) (string, error) {
	restorePrompt := r.setTemporaryPrompt(prompt)
	defer restorePrompt()

	if !r.hasInteractiveLineReader() {
		r.print("\n" + prompt)
	}

	line, err := r.readInteractiveLine()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
