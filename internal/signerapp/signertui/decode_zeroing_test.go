// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// decodedSecrets keeps every slice a capturedSecret decoded, so a test can
// see it after the decoder drops the value. decodeAs decodes into a zero T,
// so the record lives here rather than in the value.
var decodedSecrets [][]byte

// capturedSecret decodes as SensitiveBytes and records the slice it decoded.
type capturedSecret struct{ protocol.SensitiveBytes }

func (c *capturedSecret) UnmarshalJSON(data []byte) error {
	if err := c.SensitiveBytes.UnmarshalJSON(data); err != nil {
		return err
	}
	decodedSecrets = append(decodedSecrets, c.SensitiveBytes)
	return nil
}

// partialExportResult has an export_result's shape: the recovery phrase
// decodes before the word count.
type partialExportResult struct {
	Mnemonic  capturedSecret `json:"mnemonic"`
	WordCount int            `json:"word_count"`
}

// A body that decodes its secret and then fails on a later field is dropped
// with that secret zeroed, as an export_result whose recovery phrase decoded
// before a malformed word_count would be.
func TestDecodeAsZeroesSecretsOfAFailedDecode(t *testing.T) {
	decodedSecrets = nil
	t.Cleanup(func() { decodedSecrets = nil })
	decode := decodeAs(func(partialExportResult) tea.Msg { return nil })
	msg, err := decode([]byte(`{"mnemonic":"word one two","word_count":"twenty-five"}`))
	if err == nil || msg != nil {
		t.Fatalf("decode = %v, %v; want an error", msg, err)
	}
	if len(decodedSecrets) != 1 || !allZero(decodedSecrets[0]) {
		t.Fatalf("decoded secrets after the failed decode = %q, want one, zeroed", decodedSecrets)
	}
}
