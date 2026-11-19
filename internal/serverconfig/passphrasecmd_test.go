// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package serverconfig

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunPassphraseCommand(t *testing.T) {
	// Helper to create an executable script in a temp dir
	makeScript := func(t *testing.T, name, content string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}

	tests := []struct {
		name    string
		cfg     *PassphraseCommandConfig
		want    string
		wantErr string
	}{
		{
			name: "happy path - echo passphrase",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "echo-pass.sh", "#!/bin/sh\necho mysecret\n"), "arg1"},
			},
			want: "mysecret",
		},
		{
			name: "happy path - no trailing newline",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "printf-pass.sh", "#!/bin/sh\nprintf 'notrail'\n")},
			},
			want: "notrail",
		},
		{
			name: "strips exactly one trailing newline",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "double-nl.sh", "#!/bin/sh\nprintf 'secret\\n\\n'\n")},
			},
			// Two trailing newlines: strip one, keep one
			want: "secret\n",
		},
		{
			name: "preserves leading spaces",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "spaces.sh", "#!/bin/sh\nprintf '  secret  '\n")},
			},
			want: "  secret  ",
		},
		{
			name: "base64 prefix decoding",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "b64.sh", "#!/bin/sh\nprintf 'base64:"+base64.StdEncoding.EncodeToString([]byte("decoded"))+"'\n")},
			},
			want: "decoded",
		},
		{
			name: "hex prefix decoding",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "hex.sh", "#!/bin/sh\nprintf 'hex:"+hex.EncodeToString([]byte("hexval"))+"'\n")},
			},
			want: "hexval",
		},
		{
			name: "empty output",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "empty.sh", "#!/bin/sh\n")},
			},
			wantErr: "empty output",
		},
		{
			name: "non-absolute path rejected",
			cfg: &PassphraseCommandConfig{
				Argv: []string{"relative/path"},
			},
			wantErr: "absolute path",
		},
		{
			name: "empty argv",
			cfg: &PassphraseCommandConfig{
				Argv: []string{},
			},
			wantErr: "non-empty",
		},
		{
			name: "non-zero exit code",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "fail.sh", "#!/bin/sh\nexit 1\n")},
			},
			wantErr: "command failed",
		},
		{
			name: "timeout - slow command",
			cfg: &PassphraseCommandConfig{
				// Uses sh -> sleep to test that process group kill terminates children too.
				Argv: []string{makeScript(t, "slow.sh", "#!/bin/sh\nsleep 30\necho done\n")},
			},
			wantErr: "timed out",
		},
		{
			name: "nonexistent executable",
			cfg: &PassphraseCommandConfig{
				Argv: []string{"/nonexistent/binary"},
			},
			wantErr: "passphrase_command_argv",
		},
		{
			name: "NUL bytes in output",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "nul.sh", "#!/bin/sh\nprintf 'pass\\0word'\n")},
			},
			wantErr: "NUL bytes",
		},
		{
			name: "stdout exceeds limit in single write",
			cfg: &PassphraseCommandConfig{
				// Generate output larger than maxPassphraseOutputBytes (8KB) using head -c,
				// which is portable across coreutils implementations.
				Argv: []string{makeScript(t, "bigout.sh", "#!/bin/sh\nhead -c 9000 /dev/zero\n")},
			},
			wantErr: "stdout exceeded",
		},
		{
			name: "env vars passed to command",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "env.sh", "#!/bin/sh\nprintf \"$MY_SECRET\"\n")},
				Env:  map[string]string{"MY_SECRET": "fromenv"},
			},
			want: "fromenv",
		},
		{
			name: "process env NOT inherited",
			cfg: &PassphraseCommandConfig{
				Argv: []string{makeScript(t, "noenv.sh", "#!/bin/sh\nif [ -z \"$HOME\" ]; then printf 'no-home'; else printf 'has-home'; fi\n")},
			},
			want: "no-home",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip timeout test in short mode
			if tt.name == "timeout - slow command" && testing.Short() {
				t.Skip("skipping timeout test in short mode")
			}

			got, err := RunPassphraseCommand(tt.cfg, nil)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestRunPassphraseCommandVerbInjection(t *testing.T) {
	// Helper to create an executable script in a temp dir
	makeScript := func(t *testing.T, name, content string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("read verb is injected as argv1", func(t *testing.T) {
		// Script echoes its first argument (the verb)
		script := makeScript(t, "verb.sh", "#!/bin/sh\nprintf '%s' \"$1\"\n")
		cfg := &PassphraseCommandConfig{
			Argv: []string{script},
			Verb: "read",
		}
		got, err := RunPassphraseCommand(cfg, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "read" {
			t.Fatalf("got %q, want %q", string(got), "read")
		}
	})

	t.Run("write verb is injected as argv1", func(t *testing.T) {
		// Script echoes its first argument (the verb)
		script := makeScript(t, "verb.sh", "#!/bin/sh\nprintf '%s' \"$1\"\n")
		cfg := &PassphraseCommandConfig{
			Argv: []string{script},
			Verb: "write",
		}
		got, err := RunPassphraseCommand(cfg, []byte("ignored"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "write" {
			t.Fatalf("got %q, want %q", string(got), "write")
		}
	})

	t.Run("default verb is read", func(t *testing.T) {
		script := makeScript(t, "verb.sh", "#!/bin/sh\nprintf '%s' \"$1\"\n")
		cfg := &PassphraseCommandConfig{
			Argv: []string{script},
			// Verb not set — should default to "read"
		}
		got, err := RunPassphraseCommand(cfg, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "read" {
			t.Fatalf("got %q, want %q", string(got), "read")
		}
	})

	t.Run("user args follow verb", func(t *testing.T) {
		// Script echoes all arguments
		script := makeScript(t, "args.sh", "#!/bin/sh\nprintf '%s %s %s' \"$1\" \"$2\" \"$3\"\n")
		cfg := &PassphraseCommandConfig{
			Argv: []string{script, "extra1", "extra2"},
			Verb: "read",
		}
		got, err := RunPassphraseCommand(cfg, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "read extra1 extra2" {
			t.Fatalf("got %q, want %q", string(got), "read extra1 extra2")
		}
	})

	t.Run("write verb receives stdin", func(t *testing.T) {
		// Script reads stdin and echoes it back (round-trip)
		script := makeScript(t, "readback.sh", "#!/bin/sh\ncat\n")
		cfg := &PassphraseCommandConfig{
			Argv: []string{script},
			Verb: "write",
		}
		input := []byte("my-secret-passphrase")
		got, err := RunPassphraseCommand(cfg, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != "my-secret-passphrase" {
			t.Fatalf("got %q, want %q", string(got), "my-secret-passphrase")
		}
	})
}

func TestWritePassphrase(t *testing.T) {
	// Helper to create an executable script in a temp dir
	makeScript := func(t *testing.T, name, content string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("success - round-trip match", func(t *testing.T) {
		// Script reads stdin and echoes it back
		script := makeScript(t, "echo-back.sh", "#!/bin/sh\ncat\n")
		cfg := &PassphraseCommandConfig{
			Argv: []string{script},
		}
		err := WritePassphrase(cfg, []byte("test-passphrase"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("failure - read-back mismatch", func(t *testing.T) {
		// Script always returns a different value
		script := makeScript(t, "wrong.sh", "#!/bin/sh\nprintf 'wrong-value'\n")
		cfg := &PassphraseCommandConfig{
			Argv: []string{script},
		}
		err := WritePassphrase(cfg, []byte("test-passphrase"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("expected mismatch error, got %q", err.Error())
		}
	})

	t.Run("failure - write unsupported (non-zero exit)", func(t *testing.T) {
		// Script exits non-zero on write verb
		script := makeScript(t, "no-write.sh", "#!/bin/sh\nif [ \"$1\" = \"write\" ]; then exit 1; fi\ncat\n")
		cfg := &PassphraseCommandConfig{
			Argv: []string{script},
		}
		err := WritePassphrase(cfg, []byte("test-passphrase"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "command failed") {
			t.Fatalf("expected command failed error, got %q", err.Error())
		}
	})
}

// writeHelper writes an executable helper script and returns its path.
func writeHelper(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// pidFile returns a path a helper script can write a background process's
// pid to, and kills that process, and its process group, when the test ends.
func pidFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bg.pid")
	t.Cleanup(func() {
		if pid, err := readPID(path); err == nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return path
}

func readPID(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(raw)))
}

// processGone reports whether pid has gone within a few seconds, allowing for
// its new parent to reap it.
func processGone(pid int) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// A failed run leaves nothing the helper started in its process group
// running, whatever made it fail.
func TestRunPassphraseCommandFailureKillsHelperProcessGroup(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantErr string
	}{
		{name: "non-zero exit with stdout held", body: "sleep 30 &\necho $! > PIDFILE\necho mysecret\nexit 3\n", wantErr: "command failed"},
		{name: "non-zero exit", body: "sleep 30 >/dev/null &\necho $! > PIDFILE\nexit 3\n", wantErr: "command failed"},
		{name: "exit 0 with empty output", body: "sleep 30 >/dev/null &\necho $! > PIDFILE\n", wantErr: "empty output"},
		{name: "exit 0 with stdout held", body: "sleep 30 &\necho $! > PIDFILE\necho mysecret\n", wantErr: "kept its stdout open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pids := pidFile(t)
			helper := writeHelper(t, "#!/bin/sh\n"+strings.ReplaceAll(tc.body, "PIDFILE", pids))
			_, err := RunPassphraseCommand(&PassphraseCommandConfig{Argv: []string{helper}}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("RunPassphraseCommand() error = %v, want containing %q", err, tc.wantErr)
			}
			pid, err := readPID(pids)
			if err != nil {
				t.Fatalf("helper wrote no background pid: %v", err)
			}
			if !processGone(pid) {
				t.Fatalf("background process %d still running after the helper failed", pid)
			}
		})
	}
}

// A helper that prints a passphrase and exits 0, but leaves a background
// process holding its stdout, fails promptly and says so: that output is not
// settled, and the helper must not be reported as having timed out.
func TestRunPassphraseCommandHelperLeavesStdoutOpen(t *testing.T) {
	helper := writeHelper(t, "#!/bin/sh\nsleep 9 &\necho mysecret\n")
	start := time.Now()
	got, err := RunPassphraseCommand(&PassphraseCommandConfig{Argv: []string{helper}}, nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("RunPassphraseCommand() = %q, want an error for the held stdout", got)
	}
	if !strings.Contains(err.Error(), "kept its stdout open") {
		t.Fatalf("RunPassphraseCommand() error = %q, want it to name the held stdout", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("RunPassphraseCommand() took %v, want about a second", elapsed)
	}
}

// stderr is discarded, so a background process that keeps only stderr open
// changes nothing.
func TestRunPassphraseCommandIgnoresHeldStderr(t *testing.T) {
	pids := pidFile(t)
	helper := writeHelper(t, "#!/bin/sh\nsleep 9 >/dev/null &\necho $! > "+pids+"\necho mysecret\n")
	start := time.Now()
	got, err := RunPassphraseCommand(&PassphraseCommandConfig{Argv: []string{helper}}, nil)
	if err != nil {
		t.Fatalf("RunPassphraseCommand() error = %v", err)
	}
	if string(got) != "mysecret" {
		t.Fatalf("RunPassphraseCommand() = %q, want %q", got, "mysecret")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("RunPassphraseCommand() took %v, want no wait for stderr", elapsed)
	}
}

// A helper that hangs times out on time even when a process it started has
// left its process group, so the group kill cannot reach it, and holds stdout.
func TestRunPassphraseCommandTimeoutWithEscapedDescendant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}
	setsid, err := exec.LookPath("setsid")
	if err != nil {
		t.Skip("setsid not available")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	// The escaped process writes its own pid, so the cleanup finds it however
	// setsid starts it.
	pids := pidFile(t)
	helper := writeHelper(t, "#!/bin/sh\n"+setsid+" "+sh+" -c 'echo $$ > "+pids+"; exec sleep 12' &\nsleep 30\n")
	start := time.Now()
	_, err = RunPassphraseCommand(&PassphraseCommandConfig{Argv: []string{helper}}, nil)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("RunPassphraseCommand() error = %v, want a timeout", err)
	}
	if elapsed > passphraseCommandTimeout+3*time.Second {
		t.Fatalf("RunPassphraseCommand() took %v, want about %v", elapsed, passphraseCommandTimeout)
	}
}

func TestValidateAndResolveArgv(t *testing.T) {
	// Create a non-executable file
	dir := t.TempDir()
	nonExec := filepath.Join(dir, "noexec")
	if err := os.WriteFile(nonExec, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	execFile := filepath.Join(dir, "exec")
	if err := os.WriteFile(execFile, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	// Group-writable binary (explicit chmod to override umask)
	groupWritable := filepath.Join(dir, "gw")
	if err := os.WriteFile(groupWritable, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(groupWritable, 0770); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     *PassphraseCommandConfig
		wantErr string
	}{
		{
			name: "valid absolute path",
			cfg:  &PassphraseCommandConfig{Argv: []string{execFile}},
		},
		{
			name:    "empty argv",
			cfg:     &PassphraseCommandConfig{Argv: []string{}},
			wantErr: "non-empty",
		},
		{
			name:    "relative path",
			cfg:     &PassphraseCommandConfig{Argv: []string{"./script.sh"}},
			wantErr: "absolute path",
		},
		{
			name:    "not executable",
			cfg:     &PassphraseCommandConfig{Argv: []string{nonExec}},
			wantErr: "not executable",
		},
		{
			name:    "directory",
			cfg:     &PassphraseCommandConfig{Argv: []string{dir}},
			wantErr: "directory",
		},
		{
			name:    "group writable binary",
			cfg:     &PassphraseCommandConfig{Argv: []string{groupWritable}},
			wantErr: "group or world writable",
		},
		{
			name:    "bare name rejected",
			cfg:     &PassphraseCommandConfig{Argv: []string{"appass-file"}},
			wantErr: "absolute path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateAndResolveArgv(tt.cfg.Argv)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDecodePassphraseOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr string
	}{
		{
			name:  "raw bytes",
			input: []byte("plain passphrase"),
			want:  []byte("plain passphrase"),
		},
		{
			name:  "base64 prefix",
			input: []byte("base64:" + base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF})),
			want:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
		{
			name:  "hex prefix",
			input: []byte("hex:" + hex.EncodeToString([]byte{0xCA, 0xFE})),
			want:  []byte{0xCA, 0xFE},
		},
		{
			name:    "invalid base64",
			input:   []byte("base64:!!!invalid!!!"),
			wantErr: "invalid base64",
		},
		{
			name:    "invalid hex",
			input:   []byte("hex:zzzz"),
			wantErr: "invalid hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodePassphraseOutput(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != string(tt.want) {
				t.Fatalf("got %x, want %x", got, tt.want)
			}
		})
	}
}

func TestBuildPassphraseEnv(t *testing.T) {
	// Ensure CREDENTIALS_DIRECTORY is unset for baseline tests
	// t.Setenv saves/restores the original value automatically
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if err := os.Unsetenv("CREDENTIALS_DIRECTORY"); err != nil {
		t.Fatalf("failed to unset CREDENTIALS_DIRECTORY: %v", err)
	}

	// Empty map, no passthrough vars set → empty slice
	env := buildPassphraseEnv(nil)
	if len(env) != 0 {
		t.Fatalf("expected empty env, got %v", env)
	}

	// Declared vars only
	env = buildPassphraseEnv(map[string]string{
		"AWS_REGION": "us-west-2",
		"HOME":       "/var/empty",
	})
	if len(env) != 2 {
		t.Fatalf("expected 2 env vars, got %d", len(env))
	}

	// Verify format
	found := map[string]bool{}
	for _, e := range env {
		found[e] = true
	}
	if !found["AWS_REGION=us-west-2"] {
		t.Fatal("missing AWS_REGION=us-west-2")
	}
	if !found["HOME=/var/empty"] {
		t.Fatal("missing HOME=/var/empty")
	}
}

func TestBuildPassphraseEnvPassthrough(t *testing.T) {
	// t.Setenv saves/restores the original value automatically
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if err := os.Unsetenv("CREDENTIALS_DIRECTORY"); err != nil {
		t.Fatalf("failed to unset CREDENTIALS_DIRECTORY: %v", err)
	}

	t.Run("CREDENTIALS_DIRECTORY passed through when set", func(t *testing.T) {
		t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/apsigner.service")
		env := buildPassphraseEnv(nil)

		found := map[string]bool{}
		for _, e := range env {
			found[e] = true
		}
		if !found["CREDENTIALS_DIRECTORY=/run/credentials/apsigner.service"] {
			t.Fatalf("expected CREDENTIALS_DIRECTORY passthrough, got %v", env)
		}
	})

	t.Run("CREDENTIALS_DIRECTORY not passed through when unset", func(t *testing.T) {
		// Parent already unset it; t.Setenv + Unsetenv to be explicit
		t.Setenv("CREDENTIALS_DIRECTORY", "")
		if err := os.Unsetenv("CREDENTIALS_DIRECTORY"); err != nil {
			t.Fatalf("failed to unset CREDENTIALS_DIRECTORY: %v", err)
		}
		env := buildPassphraseEnv(nil)
		if len(env) != 0 {
			t.Fatalf("expected empty env, got %v", env)
		}
	})

	t.Run("declared env overrides passthrough", func(t *testing.T) {
		t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/apsigner.service")
		env := buildPassphraseEnv(map[string]string{
			"CREDENTIALS_DIRECTORY": "/custom/path",
		})

		found := map[string]bool{}
		for _, e := range env {
			found[e] = true
		}
		if !found["CREDENTIALS_DIRECTORY=/custom/path"] {
			t.Fatalf("expected declared value to win, got %v", env)
		}
		if found["CREDENTIALS_DIRECTORY=/run/credentials/apsigner.service"] {
			t.Fatal("process env should not override declared env")
		}
	})
}
