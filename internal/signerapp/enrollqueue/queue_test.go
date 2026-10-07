// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package enrollqueue

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func TestWithRequestAddsRefreshesAndCaps(t *testing.T) {
	q := &Queue{}
	key := testKey(t)
	q, entry, added, err := q.WithRequest(key, " laptop ", "10.0.0.1:1", t0)
	if err != nil || !added || entry.Label != "laptop" || entry.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatalf("first request: %+v added=%v err=%v", entry, added, err)
	}
	// A repeat refreshes the entry, keeps the label when none is given, and
	// does not duplicate it.
	q, entry, added, err = q.WithRequest(key, "", "10.0.0.2:2", t0.Add(time.Minute))
	if err != nil || added || q.Len() != 1 || entry.Label != "laptop" || entry.RemoteAddr != "10.0.0.2:2" || !entry.RequestedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("repeat request: %+v added=%v len=%d err=%v", entry, added, q.Len(), err)
	}
	for i := 1; i < MaxPending; i++ {
		if q, _, _, err = q.WithRequest(testKey(t), "", "", t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := q.WithRequest(testKey(t), "", "", t0); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("over cap error = %v, want ErrQueueFull", err)
	}
	// A key already waiting is still accepted when the queue is full.
	if _, _, added, err := q.WithRequest(key, "again", "", t0.Add(time.Hour)); err != nil || added {
		t.Fatalf("refresh at cap: added=%v err=%v", added, err)
	}
}

func TestLapsedEntriesAreDropped(t *testing.T) {
	q := &Queue{}
	old := testKey(t)
	q, _, _, _ = q.WithRequest(old, "", "", t0)
	fresh := testKey(t)
	later := t0.Add(TTL - time.Minute)
	q, _, _, _ = q.WithRequest(fresh, "", "", later)
	// Adding at TTL past the old request prunes it.
	q, _, _, err := q.WithRequest(testKey(t), "", "", t0.Add(TTL))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := q.Lookup(ssh.FingerprintSHA256(old)); ok {
		t.Fatal("lapsed request still pending")
	}
	if _, ok := q.Lookup(ssh.FingerprintSHA256(fresh)); !ok {
		t.Fatal("fresh request was dropped")
	}
	if got := q.Pruned(later.Add(TTL)).Len(); got != 1 {
		t.Fatalf("pruned len = %d, want 1 (only the newest)", got)
	}
}

func TestWithoutFingerprint(t *testing.T) {
	q := &Queue{}
	key := testKey(t)
	q, _, _, _ = q.WithRequest(key, "laptop", "", t0)
	next, entry, err := q.WithoutFingerprint(ssh.FingerprintSHA256(key))
	if err != nil || entry.Label != "laptop" || next.Len() != 0 || q.Len() != 1 {
		t.Fatalf("remove: entry=%+v next=%d orig=%d err=%v", entry, next.Len(), q.Len(), err)
	}
	if _, _, err := next.WithoutFingerprint("SHA256:missing"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("remove missing error = %v, want ErrNotPending", err)
	}
}

func TestMarshalParseRoundTripAndStrictness(t *testing.T) {
	q := &Queue{}
	a, b := testKey(t), testKey(t)
	q, _, _, _ = q.WithRequest(b, "second", "10.0.0.2:2", t0.Add(time.Second))
	q, _, _, _ = q.WithRequest(a, "first", "10.0.0.1:1", t0)
	data := q.Marshal()
	parsed, err := Parse(data, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("Parse() error = %v\n%s", err, data)
	}
	entries := parsed.Entries()
	if len(entries) != 2 || entries[0].Label != "first" || entries[1].Label != "second" || entries[0].RemoteAddr != "10.0.0.1:1" {
		t.Fatalf("round trip entries = %+v", entries)
	}
	if !entries[0].RequestedAt.Equal(t0) {
		t.Fatalf("requested_at = %v, want %v", entries[0].RequestedAt, t0)
	}
	if empty, err := Parse(nil, t0); err != nil || empty.Len() != 0 {
		t.Fatalf("Parse(nil) = %d, %v", empty.Len(), err)
	}
	for name, bad := range map[string]string{
		"unknown field":  strings.Replace(string(data), `"schema_version"`, `"extra": 1, "schema_version"`, 1),
		"schema":         strings.Replace(string(data), `"schema_version": 1`, `"schema_version": 2`, 1),
		"bad key":        strings.Replace(string(data), "ssh-ed25519 ", "ssh-ed25519 nope", 1),
		"duplicate":      strings.Replace(string(data), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(a))), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(b))), 1),
		"zero timestamp": strings.Replace(string(data), t0.Format(time.RFC3339), "0001-01-01T00:00:00Z", 1),
		"not json":       "{",
	} {
		if _, err := Parse([]byte(bad), t0); err == nil {
			t.Errorf("%s: Parse() accepted invalid document", name)
		}
	}
	// A lapsed entry parses away rather than failing the file.
	parsed, err = Parse(data, t0.Add(TTL+time.Millisecond))
	if err != nil || parsed.Len() != 1 {
		t.Fatalf("lapsed parse = %d, %v", parsed.Len(), err)
	}
}

func TestLoadAndPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", FileName)
	q, err := Load(path, t0)
	if err != nil || q.Len() != 0 {
		t.Fatalf("Load(missing) = %d, %v", q.Len(), err)
	}
	key := testKey(t)
	q, _, _, _ = q.WithRequest(key, "laptop", "", t0)
	if err := Publish(path, q); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("stat = %v, %v", info, err)
	}
	loaded, err := Load(path, t0)
	if err != nil || loaded.Len() != 1 {
		t.Fatalf("Load() = %d, %v", loaded.Len(), err)
	}
	if entry, ok := loaded.Lookup(ssh.FingerprintSHA256(key)); !ok || entry.Label != "laptop" {
		t.Fatalf("loaded entry = %+v, %v", entry, ok)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, t0); err == nil {
		t.Fatal("Load() accepted a corrupt queue")
	}
}
