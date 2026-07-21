// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/apboundedadminapp"
	"github.com/aplane-algo/aplane/internal/witness/artifact"
)

func TestGenerateInspectVerify(t *testing.T) {
	directory := t.TempDir()
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	first := []byte("test passphrase")
	second := []byte("test passphrase")
	app := application{
		stdout: stdout,
		stderr: stderr,
		readPassphrase: passphraseSequence(t,
			first,
			second,
		),
		now: func() time.Time { return time.Date(2026, time.July, 17, 1, 2, 3, 0, time.UTC) },
	}
	if exitCode := app.run([]string{"generate", "--out", directory}); exitCode != 0 {
		t.Fatalf("generate exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if !allZero(first) || !allZero(second) {
		t.Fatal("generate did not clear passphrase buffers")
	}
	var generated generateResult
	if err := json.Unmarshal(stdout.Bytes(), &generated); err != nil {
		t.Fatalf("decode generate output: %v\n%s", err, stdout.String())
	}
	if filepath.Ext(generated.ArtifactPath) != artifact.BundleExtension {
		t.Fatalf("artifact path = %q", generated.ArtifactPath)
	}

	stdout.Reset()
	stderr.Reset()
	if exitCode := app.run([]string{"inspect", generated.ArtifactPath}); exitCode != 0 {
		t.Fatalf("inspect exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	var inspected artifact.PublicReference
	if err := json.Unmarshal(stdout.Bytes(), &inspected); err != nil {
		t.Fatalf("decode inspect output: %v", err)
	}
	if inspected != generated.Reference {
		t.Fatalf("inspect = %#v, want %#v", inspected, generated.Reference)
	}

	stdout.Reset()
	stderr.Reset()
	verifyPassphrase := []byte("test passphrase")
	app.readPassphrase = passphraseSequence(t, verifyPassphrase)
	if exitCode := app.run([]string{"verify", generated.ArtifactPath}); exitCode != 0 {
		t.Fatalf("verify exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if !allZero(verifyPassphrase) {
		t.Fatal("verify did not clear passphrase buffer")
	}
	var verified verifyResult
	if err := json.Unmarshal(stdout.Bytes(), &verified); err != nil {
		t.Fatalf("decode verify output: %v", err)
	}
	if !verified.Verified || verified.WitnessKeyID != generated.Reference.WitnessKeyID {
		t.Fatalf("verify output = %#v", verified)
	}
}

func TestGenerateRejectsPassphraseMismatch(t *testing.T) {
	directory := t.TempDir()
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	app := application{
		stdout:         stdout,
		stderr:         stderr,
		readPassphrase: passphraseSequence(t, []byte("first"), []byte("second")),
		now:            time.Now,
	}
	if exitCode := app.run([]string{"generate", "--out", directory}); exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("generated files after passphrase mismatch: %v", entries)
	}
}

func TestInspectWritesTypedSchemaError(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "unknown.wit")
	if err := os.WriteFile(path, []byte(`{"schema":"aplane.external-governance-bundle.v2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	app := application{
		stdout: stdout,
		stderr: stderr,
		readPassphrase: func(string) ([]byte, error) {
			t.Fatal("unknown schema prompted for a passphrase")
			return nil, nil
		},
		now: time.Now,
	}
	for _, command := range []string{"inspect", "verify"} {
		stderr.Reset()
		if exitCode := app.run([]string{command, path}); exitCode != 1 {
			t.Fatalf("%s exit code = %d, want 1", command, exitCode)
		}
		var result protocolError
		if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
			t.Fatalf("decode %s error output: %v\n%s", command, err, stderr.String())
		}
		if result.Schema != errorSchema || result.Code != artifact.ErrorUnsupportedArtifactSchema {
			t.Fatalf("%s error output = %#v", command, result)
		}
	}
}

func TestUsageErrorsExitTwoWithoutPrompt(t *testing.T) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	app := application{
		stdout: stdout,
		stderr: stderr,
		readPassphrase: func(string) ([]byte, error) {
			t.Fatal("usage error prompted for a passphrase")
			return nil, nil
		},
		now: time.Now,
	}
	if exitCode := app.run([]string{"generate"}); exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "--out") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRekeyParsesOnlineWorkflowOptions(t *testing.T) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	var got apboundedadminapp.Options
	app := application{
		ctx:    context.Background(),
		stdout: stdout,
		stderr: stderr,
		runOnline: func(_ context.Context, options apboundedadminapp.Options, _ io.Writer) (*apboundedadminapp.Result, error) {
			got = options
			return &apboundedadminapp.Result{TxID: "TXID", Confirmed: true}, nil
		},
	}
	exitCode := app.run([]string{
		"rekey", "--client-data", "/client", "--network", "localnet", "--key", "/cold/key.wit",
		"--fee", "4000", "account", "to", "target",
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if got.Operation != apboundedadminapp.OperationRekey || got.ClientData != "/client" || got.Network != "localnet" || got.Artifact != "/cold/key.wit" || got.Account != "account" || got.Target != "target" || got.Fee != 4000 || !got.UseFlatFee || !got.Wait {
		t.Fatalf("options = %#v", got)
	}
	if !strings.Contains(stdout.String(), "TXID") || !strings.Contains(stdout.String(), "confirmed") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestUnrekeyParsesNowait(t *testing.T) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	var got apboundedadminapp.Options
	app := application{
		stdout: stdout,
		stderr: stderr,
		runOnline: func(_ context.Context, options apboundedadminapp.Options, _ io.Writer) (*apboundedadminapp.Result, error) {
			got = options
			return &apboundedadminapp.Result{TxID: "TXID"}, nil
		},
	}
	if exitCode := app.run([]string{"unrekey", "--key", "/cold/key.wit", "--nowait", "account"}); exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if got.Operation != apboundedadminapp.OperationUnrekey || got.Account != "account" || got.Target != "" || got.Wait {
		t.Fatalf("options = %#v", got)
	}
}

func passphraseSequence(t *testing.T, passphrases ...[]byte) func(string) ([]byte, error) {
	t.Helper()
	next := 0
	return func(string) ([]byte, error) {
		if next >= len(passphrases) {
			t.Fatal("unexpected passphrase prompt")
		}
		passphrase := passphrases[next]
		next++
		return passphrase, nil
	}
}

func allZero(data []byte) bool {
	return bytes.Equal(data, make([]byte, len(data)))
}

func TestCompleteRejectsDoubleStdin(t *testing.T) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	app := application{
		stdout: stdout,
		stderr: stderr,
		stdin:  strings.NewReader("{}"),
		now:    time.Now,
	}
	if exitCode := app.run([]string{"complete", "-", "with", "-"}); exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "cannot both be read from stdin") {
		t.Fatalf("stderr = %q, want double-stdin rejection", stderr.String())
	}
}
