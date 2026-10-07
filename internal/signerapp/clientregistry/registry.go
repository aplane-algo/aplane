// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package clientregistry parses and writes the signer's enrolled client key
// registry, the identity's authorized_keys file.
//
// The file keeps OpenSSH's line syntax so it stays readable by people and by
// ssh-keygen, but the semantics are APlane's own and strict: this version
// implements no options, so every option-bearing line is rejected (including
// any under the reserved "aplane-" prefix), malformed lines and duplicate keys
// reject the whole file with a line number, and the registry loads completely
// or not at all. An option-free line is a client key. A comment after the key
// is a display label that never grants authority.
package clientregistry

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ReservedOptionPrefix is held for future APlane options. Reserving it does
// not make options under it acceptable to a version that does not implement
// them.
const ReservedOptionPrefix = "aplane-"

// Entry is one enrolled key.
type Entry struct {
	Key ssh.PublicKey
	// Fingerprint is the SHA256 fingerprint of Key, the client's stable
	// identity.
	Fingerprint string
	// Label is the optional comment after the key: display information only.
	Label string
}

// Registry is a parsed, validated registry. The zero value is empty.
type Registry struct {
	entries []Entry
	byKey   map[string]int // canonical key bytes -> index
}

// Error reports a rejected registry with the offending line.
type Error struct {
	Line   int
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("authorized_keys line %d: %s", e.Line, e.Reason)
}

// ErrNotEnrolled reports a key the registry does not hold.
var ErrNotEnrolled = errors.New("key is not enrolled")

// MaxLabelBytes bounds a display label. The SSH enrollment command enforces
// the same bound and character rule on client-supplied labels.
const MaxLabelBytes = 64

// NormalizeLabel trims label and checks that it is a bounded, printable,
// single-line display text, the only form the registry writes: a label is
// emitted verbatim after the key on its authorized_keys line, so a line
// break would become a key line of its own.
func NormalizeLabel(label string) (string, error) {
	label = strings.TrimSpace(label)
	if len(label) > MaxLabelBytes {
		return "", fmt.Errorf("label exceeds %d bytes", MaxLabelBytes)
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("label must be printable single-line text")
		}
	}
	return label, nil
}

// Parse validates data as a complete registry. Blank lines and "#" comment
// lines are allowed; everything else must be an option-free public-key line.
func Parse(data []byte) (*Registry, error) {
	reg := &Registry{byKey: make(map[string]int)}
	lines := bytes.Split(data, []byte("\n"))
	lineOfEntry := make([]int, 0, len(lines))
	for i, raw := range lines {
		lineNo := i + 1
		line := bytes.TrimRight(raw, "\r")
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		key, comment, options, rest, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, &Error{Line: lineNo, Reason: "malformed public key line"}
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, &Error{Line: lineNo, Reason: "unexpected trailing content"}
		}
		if len(options) != 0 {
			return nil, &Error{Line: lineNo, Reason: fmt.Sprintf("option %q is not implemented by this version", options[0])}
		}
		if idx, dup := reg.indexOf(key); dup {
			return nil, &Error{Line: lineNo, Reason: fmt.Sprintf("duplicate of the key on line %d", lineOfEntry[idx])}
		}
		reg.add(key, comment)
		lineOfEntry = append(lineOfEntry, lineNo)
	}
	return reg, nil
}

func (r *Registry) indexOf(key ssh.PublicKey) (int, bool) {
	if r == nil || r.byKey == nil || key == nil {
		return 0, false
	}
	idx, ok := r.byKey[string(key.Marshal())]
	return idx, ok
}

func (r *Registry) add(key ssh.PublicKey, label string) {
	if r.byKey == nil {
		r.byKey = make(map[string]int)
	}
	r.byKey[string(key.Marshal())] = len(r.entries)
	r.entries = append(r.entries, Entry{
		Key:         key,
		Fingerprint: ssh.FingerprintSHA256(key),
		Label:       strings.TrimSpace(label),
	})
}

// Len returns the number of enrolled keys.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.entries)
}

// Entries returns the enrolled keys in file order.
func (r *Registry) Entries() []Entry {
	if r == nil {
		return nil
	}
	out := make([]Entry, len(r.entries))
	copy(out, r.entries)
	return out
}

// Lookup returns the entry for key, compared by canonical key bytes.
func (r *Registry) Lookup(key ssh.PublicKey) (Entry, bool) {
	idx, ok := r.indexOf(key)
	if !ok {
		return Entry{}, false
	}
	return r.entries[idx], true
}

// LookupFingerprint returns the entry whose key has the given SHA256
// fingerprint.
func (r *Registry) LookupFingerprint(fingerprint string) (Entry, bool) {
	if r == nil {
		return Entry{}, false
	}
	for _, e := range r.entries {
		if e.Fingerprint == fingerprint {
			return e, true
		}
	}
	return Entry{}, false
}

// Has reports whether key is enrolled.
func (r *Registry) Has(key ssh.PublicKey) bool {
	_, ok := r.indexOf(key)
	return ok
}

// WithKey returns a copy of the registry with key added. Adding a key that is
// already enrolled returns an equal copy and false, so enrollment is
// idempotent and writes nothing.
func (r *Registry) WithKey(key ssh.PublicKey, label string) (*Registry, bool) {
	out := r.clone()
	if out.Has(key) {
		return out, false
	}
	out.add(key, label)
	return out, true
}

// WithoutFingerprint returns a copy of the registry without the key that has
// the given fingerprint. It returns ErrNotEnrolled when no entry matches.
func (r *Registry) WithoutFingerprint(fingerprint string) (*Registry, error) {
	out := &Registry{byKey: make(map[string]int)}
	found := false
	if r != nil {
		for _, e := range r.entries {
			if e.Fingerprint == fingerprint {
				found = true
				continue
			}
			out.add(e.Key, e.Label)
		}
	}
	if !found {
		return nil, ErrNotEnrolled
	}
	return out, nil
}

func (r *Registry) clone() *Registry {
	out := &Registry{byKey: make(map[string]int)}
	if r == nil {
		return out
	}
	for _, e := range r.entries {
		out.add(e.Key, e.Label)
	}
	return out
}

// Marshal renders the registry as option-free authorized_keys lines, one per
// entry, in order. Parse(Marshal(r)) equals r.
func (r *Registry) Marshal() []byte {
	if r == nil {
		return nil
	}
	var buf bytes.Buffer
	for _, e := range r.entries {
		buf.Write(bytes.TrimRight(ssh.MarshalAuthorizedKey(e.Key), "\n"))
		if e.Label != "" {
			buf.WriteByte(' ')
			buf.WriteString(e.Label)
		}
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}
