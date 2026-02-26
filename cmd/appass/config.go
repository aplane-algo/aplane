// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// configHasKey returns true if the config file contains a line starting with "key:".
// Comments (lines starting with #) are skipped.
func configHasKey(path, key string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("could not open config: %w", err)
	}
	defer func() { _ = f.Close() }()

	prefix := key + ":"
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, prefix) {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// configAppendLines appends the given lines to the config file.
// A leading newline is added if the file does not end with one.
func configAppendLines(path string, lines []string) error {
	// Check if file ends with newline
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read config: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("could not open config for writing: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Ensure we start on a new line
	if len(data) > 0 && data[len(data)-1] != '\n' {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}

	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return nil
}

// configRemoveKeys removes all lines whose key (text before the first ':') matches
// any of the given keys. Comment lines are preserved.
func configRemoveKeys(path string, keys []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read config: %w", err)
	}

	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}

	var kept []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Always keep comments and blank lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			kept = append(kept, line)
			continue
		}

		// Check if this line's key is in the removal set
		colonIdx := strings.IndexByte(trimmed, ':')
		if colonIdx != -1 {
			lineKey := strings.TrimSpace(trimmed[:colonIdx])
			if keySet[lineKey] {
				continue // skip this line
			}
		}

		kept = append(kept, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning config: %w", err)
	}

	output := strings.Join(kept, "\n")
	if len(kept) > 0 {
		output += "\n"
	}

	return os.WriteFile(path, []byte(output), 0640)
}
