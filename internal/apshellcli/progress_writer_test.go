// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

func TestProgressLineWriterRoutesToProgressLineOrOut(t *testing.T) {
	eng := engine.NewEngine("localnet")
	state := &REPLState{
		App:     apshellapp.New(eng, config.DefaultConfig(), t.TempDir()),
		DataDir: t.TempDir(),
	}
	var out bytes.Buffer
	state.SetOutput(&out)
	state.App.SetProgressOutput(&progressLineWriter{emit: state.progressPrintln})

	w := eng.Connection.ProgressOutput()
	if w == nil {
		t.Fatal("SetProgressOutput did not wire Connection.ProgressOutput")
	}

	// Split chunks and CRLF are buffered until newline and routed to Out when
	// ProgressLine is unset.
	if _, err := io.WriteString(w, "Waiting for "); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("flushed partial line early: %q", out.String())
	}
	if _, err := io.WriteString(w, "approval...\r\nDone\n"); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "Waiting for approval...\nDone\n"; got != want {
		t.Fatalf("Out = %q, want %q", got, want)
	}

	// Once a TUI host installs ProgressLine, live progress lines go there
	// instead of the captured Out buffer.
	out.Reset()
	var live []string
	state.ProgressLine = func(line string) {
		live = append(live, line)
	}
	if _, err := io.WriteString(w, "Waiting for approval from Signer...\n"); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("Out received live progress while ProgressLine was set: %q", out.String())
	}
	if want := []string{"Waiting for approval from Signer..."}; !reflect.DeepEqual(live, want) {
		t.Fatalf("ProgressLine = %q, want %q", live, want)
	}
}
