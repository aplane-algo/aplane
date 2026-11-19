// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
)

const historyLimit = 1000

// historyFileMode is the history file's mode: owner-only, since it holds
// what the user typed, addresses, inline js code and plugin arguments.
const historyFileMode = 0o600

// historyFilePath is ~/.apshell_history, or "" when the home directory is
// unknown, which turns history off rather than writing it to whatever
// directory apshell was started from.
func historyFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		return ""
	}
	return filepath.Join(homeDir, ".apshell_history")
}

// loadHistoryFile returns the last historyLimit entries of the history file
// at path.
func loadHistoryFile(path string) []string {
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()

	var entries []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entries = append(entries, line)
	}
	if len(entries) > historyLimit {
		entries = entries[len(entries)-historyLimit:]
	}
	return entries
}

func appendHistoryFile(path, line string) {
	line = strings.TrimSpace(line)
	if path == "" || line == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, historyFileMode)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	// A file an earlier apshell, or readline, created is made owner-only too.
	_ = file.Chmod(historyFileMode)
	_, _ = file.WriteString(line + "\n")
}

// restrictHistoryFile creates path owner-only, or makes an existing file
// owner-only, without changing its content.
func restrictHistoryFile(path string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, historyFileMode)
	if err != nil {
		return
	}
	_ = file.Chmod(historyFileMode)
	_ = file.Close()
}

// newReadlineWithPrivateHistory is readline.NewEx with cfg's history file
// kept owner-only. readline creates the file with mode 0666 less the umask,
// and when it holds more than the limit rewrites it through "<file>.tmp",
// created the same way and renamed over it; readline v1.5.1 rewrites only
// while NewEx opens the file. Both files are created owner-only first, so
// readline's create and truncate keep that mode and no other user can open
// either in between, and once NewEx returns the history file is made
// owner-only again and the temporary file, if readline left it, removed.
func newReadlineWithPrivateHistory(cfg *readline.Config) (*readline.Instance, error) {
	path := cfg.HistoryFile
	if path == "" {
		return readline.NewEx(cfg)
	}
	restrictHistoryFile(path)
	restrictHistoryFile(path + ".tmp")
	rl, err := readline.NewEx(cfg)
	_ = os.Chmod(path, historyFileMode)
	_ = os.Remove(path + ".tmp")
	return rl, err
}
