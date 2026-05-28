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

func (r *REPLState) readApprovalResponse() (string, error) {
	return r.readPromptResponse("Proceed with signing and submission? [y/N]: ")
}

func (r *REPLState) readDeleteKeyResponse(address string) (string, error) {
	return r.readPromptResponse("Delete key " + r.app().FormatAddress(address, "") + "? [y/N]: ")
}

func (r *REPLState) readPromptResponse(prompt string) (string, error) {
	restorePrompt := r.setTemporaryPrompt(prompt)
	defer restorePrompt()

	if r.LineReader == nil {
		r.print("\n" + prompt)
	}

	line, err := r.readInteractiveLine()
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(line)), nil
}
