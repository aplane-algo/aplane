// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package enrollqueue holds the enrollment requests waiting for an operator.
//
// A client that asks to be enrolled submits its public key and returns at
// once; the request waits here until the operator approves it (which moves
// the key into the enrolled registry) or rejects it. The queue is persisted
// in the product store so a request survives a daemon restart, and it is
// bounded because its writers are unauthenticated: one entry per key, a cap
// on entries, and a lifetime after which an entry lapses.
package enrollqueue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// SchemaVersion is the on-disk document version.
	SchemaVersion = 1
	// MaxPending caps the queue. A client that finds it full is told so and
	// may try again later; the operator can clear entries at any time.
	MaxPending = 16
	// TTL is how long a request waits before it lapses. A client whose
	// request lapsed simply requests again.
	TTL = 7 * 24 * time.Hour
)

var (
	// ErrQueueFull reports a request refused because the queue is at MaxPending.
	ErrQueueFull = errors.New("enrollment queue is full")
	// ErrNotPending reports a fingerprint with no pending request.
	ErrNotPending = errors.New("no pending enrollment request for key")
)

// Entry is one pending request.
type Entry struct {
	Key ssh.PublicKey
	// Fingerprint is the SHA256 fingerprint of Key.
	Fingerprint string
	// Label is the display label the client asked for.
	Label string
	// RemoteAddr is where the request came from.
	RemoteAddr string
	// RequestedAt is when the request was made or last refreshed.
	RequestedAt time.Time
}

// Queue is a parsed, validated queue ordered oldest first. The zero value is
// empty. Queues are values: mutations return a new queue.
type Queue struct {
	entries []Entry
}

type document struct {
	SchemaVersion int         `json:"schema_version"`
	Requests      []document0 `json:"requests"`
}

type document0 struct {
	PublicKey   string    `json:"public_key"`
	Label       string    `json:"label,omitempty"`
	RemoteAddr  string    `json:"remote_addr,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
}

// Parse validates data as a complete queue and drops entries that lapsed
// before now. Empty data is an empty queue.
func Parse(data []byte, now time.Time) (*Queue, error) {
	q := &Queue{}
	if len(bytes.TrimSpace(data)) == 0 {
		return q, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var doc document
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("enrollment queue: %w", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("enrollment queue: schema_version = %d, want %d", doc.SchemaVersion, SchemaVersion)
	}
	seen := map[string]bool{}
	for i, raw := range doc.Requests {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(raw.PublicKey)))
		if err != nil {
			return nil, fmt.Errorf("enrollment queue: request %d: invalid public key: %w", i+1, err)
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if seen[fingerprint] {
			return nil, fmt.Errorf("enrollment queue: request %d: duplicate key %s", i+1, fingerprint)
		}
		seen[fingerprint] = true
		if raw.RequestedAt.IsZero() {
			return nil, fmt.Errorf("enrollment queue: request %d: requested_at is required", i+1)
		}
		if expired(raw.RequestedAt, now) {
			continue
		}
		q.entries = append(q.entries, Entry{
			Key:         key,
			Fingerprint: fingerprint,
			Label:       strings.TrimSpace(raw.Label),
			RemoteAddr:  strings.TrimSpace(raw.RemoteAddr),
			RequestedAt: raw.RequestedAt,
		})
	}
	q.sortEntries()
	return q, nil
}

func expired(requestedAt, now time.Time) bool {
	return !now.Before(requestedAt.Add(TTL))
}

func (q *Queue) sortEntries() {
	sort.SliceStable(q.entries, func(i, j int) bool {
		return q.entries[i].RequestedAt.Before(q.entries[j].RequestedAt)
	})
}

// Len returns the number of pending requests.
func (q *Queue) Len() int {
	if q == nil {
		return 0
	}
	return len(q.entries)
}

// Entries returns the pending requests, oldest first.
func (q *Queue) Entries() []Entry {
	if q == nil {
		return nil
	}
	return append([]Entry(nil), q.entries...)
}

// Lookup returns the pending request for a key fingerprint.
func (q *Queue) Lookup(fingerprint string) (Entry, bool) {
	if q == nil {
		return Entry{}, false
	}
	for _, entry := range q.entries {
		if entry.Fingerprint == fingerprint {
			return entry, true
		}
	}
	return Entry{}, false
}

// WithRequest records a request for key at now. A key that is already
// waiting has its entry refreshed rather than duplicated, and does not count
// against the cap; added reports whether the key was new to the queue.
// Lapsed entries are dropped first.
func (q *Queue) WithRequest(key ssh.PublicKey, label, remoteAddr string, now time.Time) (next *Queue, entry Entry, added bool, err error) {
	if key == nil {
		return nil, Entry{}, false, fmt.Errorf("enrollment queue: key is required")
	}
	out := q.pruned(now)
	fingerprint := ssh.FingerprintSHA256(key)
	entry = Entry{
		Key:         key,
		Fingerprint: fingerprint,
		Label:       strings.TrimSpace(label),
		RemoteAddr:  strings.TrimSpace(remoteAddr),
		RequestedAt: now,
	}
	for i := range out.entries {
		if out.entries[i].Fingerprint == fingerprint {
			if entry.Label == "" {
				entry.Label = out.entries[i].Label
			}
			out.entries[i] = entry
			out.sortEntries()
			return out, entry, false, nil
		}
	}
	if len(out.entries) >= MaxPending {
		return nil, Entry{}, false, ErrQueueFull
	}
	out.entries = append(out.entries, entry)
	out.sortEntries()
	return out, entry, true, nil
}

// WithoutFingerprint removes the pending request for a key.
func (q *Queue) WithoutFingerprint(fingerprint string) (*Queue, Entry, error) {
	out := q.clone()
	for i, entry := range out.entries {
		if entry.Fingerprint == fingerprint {
			out.entries = append(out.entries[:i:i], out.entries[i+1:]...)
			return out, entry, nil
		}
	}
	return nil, Entry{}, ErrNotPending
}

// Pruned returns the queue without entries that lapsed before now.
func (q *Queue) Pruned(now time.Time) *Queue {
	return q.pruned(now)
}

func (q *Queue) pruned(now time.Time) *Queue {
	out := &Queue{}
	if q == nil {
		return out
	}
	for _, entry := range q.entries {
		if !expired(entry.RequestedAt, now) {
			out.entries = append(out.entries, entry)
		}
	}
	return out
}

func (q *Queue) clone() *Queue {
	out := &Queue{}
	if q != nil {
		out.entries = append([]Entry(nil), q.entries...)
	}
	return out
}

// Marshal renders the queue as its on-disk document.
func (q *Queue) Marshal() []byte {
	doc := document{SchemaVersion: SchemaVersion, Requests: []document0{}}
	for _, entry := range q.Entries() {
		doc.Requests = append(doc.Requests, document0{
			PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(entry.Key))),
			Label:       entry.Label,
			RemoteAddr:  entry.RemoteAddr,
			RequestedAt: entry.RequestedAt.UTC(),
		})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		// Only our own fixed types are marshaled.
		panic(err)
	}
	return append(data, '\n')
}
