// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
)

// RotatingRelease is a ROTATING_RELEASE entry read back from the audit log.
type RotatingRelease struct {
	Account   string
	Stage     uint64
	TxID      string
	LastValid uint64
	// Reused reports that an earlier entry in the logs read names the same
	// account and stage with a different TxID. Entries the log has rotated
	// past cannot be seen, so false means none was seen, not none was made.
	Reused bool
}

// ReadRotatingReleases returns the newest ROTATING_RELEASE entry per account
// from the audit log at path and its rotated predecessors (path+".2", then
// path+".1", then path), oldest first so later entries win. Entries that no
// longer exist because the log rotated past them are simply absent: the
// release memory this feeds is observational and degrades to silence, never
// to a wrong signature. Malformed lines are skipped.
func ReadRotatingReleases(path string) (map[string]RotatingRelease, error) {
	out := make(map[string]RotatingRelease)
	for _, file := range []string{path + ".2", path + ".1", path} {
		if err := readRotatingReleasesFrom(file, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readRotatingReleasesFrom(file string, out map[string]RotatingRelease) error {
	f, err := os.Open(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Event != AuditRotatingRelease || entry.TxnAuth == "" || entry.RotatingStage == nil {
			continue
		}
		r := RotatingRelease{
			Account:   entry.TxnAuth,
			Stage:     *entry.RotatingStage,
			TxID:      entry.TxID,
			LastValid: entry.RotatingLastValid,
		}
		if prev, ok := out[r.Account]; ok && prev.Stage == r.Stage {
			r.Reused = prev.Reused || prev.TxID != r.TxID
		}
		out[r.Account] = r
	}
	return scanner.Err()
}
