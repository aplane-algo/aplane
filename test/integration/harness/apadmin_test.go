// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestUnlockHelperProcess(t *testing.T) {
	mode := os.Getenv("APLANE_UNLOCK_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "delayed":
		time.Sleep(750 * time.Millisecond)
		fmt.Println("Signer unlocked")
	case "exit":
		fmt.Fprintln(os.Stderr, "authentication failed: test rejection")
		os.Exit(1)
	case "timeout":
		fmt.Println("still authenticating")
	}
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestStartUnlockCommand(t *testing.T) {
	for _, tc := range []struct {
		name      string
		timeout   time.Duration
		wantError string
	}{
		{"delayed", 5 * time.Second, ""},
		{"exit", 5 * time.Second, "authentication failed: test rejection"},
		{"timeout", 500 * time.Millisecond, "timed out waiting for signer unlock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestUnlockHelperProcess$")
			cmd.Env = append(os.Environ(), "APLANE_UNLOCK_HELPER="+tc.name)
			start := time.Now()
			done, err := startUnlockCommand(cmd, tc.timeout)
			if tc.wantError != "" {
				if err == nil {
					_ = cmd.Process.Kill()
					<-done
					t.Fatal("expected startup failure")
				}
				if !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("unexpected error: %v", err)
				}
				if cmd.ProcessState == nil {
					t.Fatal("failed process was not reaped")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); <-done }()
			if time.Since(start) < 750*time.Millisecond {
				t.Fatal("returned before delayed readiness")
			}
		})
	}
}
