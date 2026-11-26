// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// lockedBuffer is a bytes.Buffer the limiter writes to while a test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Split(strings.TrimSpace(b.buf.String()), "\n")
}

// The first lines print, then one per refill, and the rest are counted.
func TestUnenrolledLogPrintsABurstThenCounts(t *testing.T) {
	var out lockedBuffer
	l := newUnenrolledLog(&out)
	t.Cleanup(l.close)
	now := time.Unix(1_000, 0)
	l.now = func() time.Time { return now }
	for i := range unenrolledLogBurst + 5 {
		l.printf("line %d\n", i)
	}
	if got := len(out.lines()); got != unenrolledLogBurst {
		t.Fatalf("printed %d lines of %d, want %d", got, unenrolledLogBurst+5, unenrolledLogBurst)
	}
	// A token comes back every 3 seconds, as ARCH_SECURITY.md says.
	now = now.Add(2900 * time.Millisecond)
	l.printf("too soon\n")
	now = now.Add(100 * time.Millisecond)
	l.printf("after a refill\n")
	l.printf("past it\n")
	l.flush()
	lines := out.lines()
	if got := lines[len(lines)-2]; got != "after a refill" {
		t.Fatalf("line after a refill = %q", got)
	}
	if got := lines[len(lines)-1]; got != "[SSH] 7 more lines about connections without an enrolled key were not printed" {
		t.Fatalf("summary = %q", got)
	}
	l.flush()
	if got := len(out.lines()); got != len(lines) {
		t.Fatalf("a second flush printed again: %d lines, want %d", got, len(lines))
	}
	now = now.Add(time.Hour)
	for range unenrolledLogBurst + 1 {
		l.printf("later\n")
	}
	if got := len(out.lines()) - len(lines); got != unenrolledLogBurst {
		t.Fatalf("after an hour %d lines printed, want the burst of %d", got, unenrolledLogBurst)
	}
}

// A flood of connections with keys nobody enrolled prints a bounded number of
// lines, and the count of the rest.
func TestAFloodOfUnknownKeysPrintsBoundedLines(t *testing.T) {
	srv, _ := testServer(t)
	srv.SetProductHooks(newEnrolledSet().hooks())
	var out lockedBuffer
	srv.unenrolled = newUnenrolledLog(&out)
	now := time.Unix(1_000, 0)
	srv.unenrolled.now = func() time.Time { return now }
	addr := serveConnections(t, srv)
	const dials = 40
	for range dials {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            productSSHUsername,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
			Timeout:         5 * time.Second,
		}); err == nil {
			t.Fatal("an unknown key was admitted")
		}
	}
	srv.unenrolled.flush()
	lines := out.lines()
	// 20, as ARCH_SECURITY.md says, and the count.
	if len(lines) != 21 {
		t.Fatalf("%d dials printed %d lines, want 20 and a count:\n%s", dials, len(lines), strings.Join(lines, "\n"))
	}
	if last := lines[len(lines)-1]; !strings.Contains(last, "were not printed") {
		t.Fatalf("no count of the rest: %q", last)
	}
	printed := strings.Join(lines, "\n")
	for _, want := range []string{"outcome=rejected", "Rejected unknown key"} {
		if !strings.Contains(printed, want) {
			t.Errorf("no %q line went through the limit:\n%s", want, printed)
		}
	}
}

// An enrollment connection proves only that it holds its key, so what it
// prints goes through the same limit.
func TestEnrollmentLinesGoThroughTheLimit(t *testing.T) {
	srv, _ := testServer(t)
	setEnrollmentHooks(srv, EnrollmentHooks{Request: pendingHook(nil)})
	var out lockedBuffer
	srv.unenrolled = newUnenrolledLog(&out)
	addr := serveConnections(t, srv)
	for _, command := range []string{"enroll laptop", "bogus", "enroll bad\x1blabel"} {
		client := dialEnrollment(t, srv, addr)
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = session.CombinedOutput(command)
		_ = client.Close()
	}
	want := []string{"outcome=accepted", "Enrollment request recorded", "Unknown enrollment command",
		"refused", "Client connected", "Client disconnected"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		printed := strings.Join(out.lines(), "\n")
		missing := ""
		for _, line := range want {
			if !strings.Contains(printed, line) {
				missing = line
				break
			}
		}
		// The line the key's admission prints, apart from the refusal's.
		if missing == "" && !regexp.MustCompile(`Enrollment request from \S+ \(key: `).MatchString(printed) {
			missing = "Enrollment request from <addr> (key:"
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %q line went through the limit:\n%s", missing, printed)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An enrolled client's lines are not limited.
func TestEnrolledClientLinesAreNotLimited(t *testing.T) {
	srv, tmpDir := testServer(t)
	set := newEnrolledSet()
	srv.SetProductHooks(set.hooks())
	var out lockedBuffer
	srv.unenrolled = newUnenrolledLog(&out)
	host, port, known := startServer(t, srv, tmpDir)
	// More connections than the burst: the "none" each client tries before its
	// key spends nothing either.
	for range unenrolledLogBurst + 5 {
		client, _ := connectEnrolledClient(t, srv, set, tmpDir, host, port, known)
		_ = client.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if got := strings.TrimSpace(strings.Join(out.lines(), "\n")); got != "" {
		t.Fatalf("an enrolled client's lines went through the limit:\n%s", got)
	}
	srv.unenrolled.mu.Lock()
	tokens := srv.unenrolled.tokens
	srv.unenrolled.mu.Unlock()
	if tokens != unenrolledLogBurst {
		t.Fatalf("%d of %d tokens left", tokens, unenrolledLogBurst)
	}
}

// The count of what was not printed arrives on its own, a while after the
// first line it holds back.
func TestTheUnenrolledSummaryArrivesOnItsOwn(t *testing.T) {
	var out lockedBuffer
	l := newUnenrolledLog(&out)
	t.Cleanup(l.close)
	l.summaryAfter = 20 * time.Millisecond
	l.tokens = 0
	l.printf("held back\n")
	l.printf("held back\n")
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(strings.Join(out.lines(), "\n"), "2 more lines") {
		if time.Now().After(deadline) {
			t.Fatalf("no summary arrived: %q", out.lines())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if unenrolledLogSummaryAfter != time.Minute {
		t.Fatalf("the summary waits %v, not the minute ARCH_SECURITY.md says", unenrolledLogSummaryAfter)
	}
}

// Once the server stops, the count of what was not printed is printed, and a
// line a late handler prints arms no summary.
func TestAClosedUnenrolledLogArmsNoSummary(t *testing.T) {
	var out lockedBuffer
	l := newUnenrolledLog(&out)
	l.tokens = 0
	l.printf("suppressed\n")
	l.close()
	if got := out.lines(); len(got) != 1 || !strings.Contains(got[0], "1 more line about") {
		t.Fatalf("close printed %q, want the count", got)
	}
	l.printf("late\n")
	l.mu.Lock()
	armed := l.summary != nil
	l.mu.Unlock()
	if armed {
		t.Fatal("a line after close armed a summary")
	}
}

// Stopping the server prints the count of what was not printed.
func TestStopPrintsTheUnenrolledCount(t *testing.T) {
	srv, tmpDir := testServer(t)
	var out lockedBuffer
	srv.unenrolled = newUnenrolledLog(&out)
	srv.unenrolled.tokens = 0
	startServer(t, srv, tmpDir)
	srv.unenrolled.printf("suppressed\n")
	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := out.lines(); len(got) != 1 || !strings.Contains(got[0], "1 more line about") {
		t.Fatalf("after Stop the log has %q, want the count", got)
	}
}
