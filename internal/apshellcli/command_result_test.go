// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"io"
	"testing"
)

func TestStructuredCommandResultRejectsMissingOrInvalidMachineJSON(t *testing.T) {
	for _, data := range [][]byte{nil, []byte{}, []byte("not-json")} {
		if _, err := newShellCommandJSONResult(nil, data); err == nil {
			t.Fatalf("newShellCommandJSONResult(%q) error = nil", data)
		}
	}
}

func TestCompletedCommandResultCanRenderRepeatedlyWithoutMutation(t *testing.T) {
	calls := 0
	result, err := newShellCommandResult(func(w io.Writer) error {
		calls++
		_, err := io.WriteString(w, "human\n")
		return err
	}, struct {
		Value string `json:"value"`
	}{Value: "machine"})
	if err != nil {
		t.Fatal(err)
	}

	var first, second bytes.Buffer
	if err := result.RenderText(&first); err != nil {
		t.Fatal(err)
	}
	if err := result.RenderText(&second); err != nil {
		t.Fatal(err)
	}
	one, err := result.MarshalMachine()
	if err != nil {
		t.Fatal(err)
	}
	two, err := result.MarshalMachine()
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "human\n" || second.String() != first.String() || !bytes.Equal(one, two) {
		t.Fatalf("rendering drifted: text=(%q,%q) machine=(%q,%q)", first.String(), second.String(), one, two)
	}
	if calls != 2 {
		t.Fatalf("text presentation calls = %d, want 2", calls)
	}
}
