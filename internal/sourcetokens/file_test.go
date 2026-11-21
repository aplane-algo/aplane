// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sourcetokens

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
)

const (
	testKeyID      = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	otherTestKeyID = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ"
)

var testSetAt = time.Date(2026, 11, 21, 10, 30, 0, 0, time.UTC)

func testKeyring(t *testing.T) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Zero)
	return kr
}

func mustSet(t *testing.T, current *File, selector, source, value string) *File {
	t.Helper()
	next, err := SetToken(current, selector, source, []byte(value), testSetAt)
	if err != nil {
		t.Fatalf("SetToken(%s, %s) error = %v", selector, source, err)
	}
	return next
}

func TestEncodeIsCanonicalAndDecodesBack(t *testing.T) {
	f := mustSet(t, nil, testKeyID, "screening", `Bearer-"quoted"\back`)
	f = mustSet(t, f, testKeyID, "ops", "abc")
	encoded, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"format":"aplane.source-tokens.v1","selector":"` + testKeyID + `","tokens":{` +
		`"ops":{"set_at":"2026-11-21T10:30:00Z","value":"abc"},` +
		`"screening":{"set_at":"2026-11-21T10:30:00Z","value":"Bearer-\"quoted\"\\back"}}}`
	if string(encoded) != want {
		t.Fatalf("Encode() =\n%s\nwant\n%s", encoded, want)
	}
	if len(encoded) != cap(encoded) {
		t.Fatalf("Encode() buffer has %d spare bytes; it should be sized exactly", cap(encoded)-len(encoded))
	}
	decoded, err := Decode(encoded, testKeyID)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got := string(decoded.Tokens["screening"].Value); got != `Bearer-"quoted"\back` {
		t.Fatalf("decoded screening token = %q", got)
	}
	if got := decoded.Listing(); len(got) != 2 || got[0].Source != "ops" || got[1].Source != "screening" || !got[0].SetAt.Equal(testSetAt) {
		t.Fatalf("Listing() = %+v", got)
	}
}

// Decode accepts only what Encode writes, and its errors never quote a token.
func TestDecodeRefusesAnythingButCanonicalForm(t *testing.T) {
	const secret = "s3cret-token"
	head := `{"format":"aplane.source-tokens.v1","selector":"` + testKeyID + `","tokens":{`
	entry := `"ops":{"set_at":"2026-11-21T10:30:00Z","value":"` + secret + `"}`
	tests := map[string]string{
		"unknown member":           head + entry + `},"extra":1}`,
		"unknown token member":     head + `"ops":{"set_at":"2026-11-21T10:30:00Z","value":"` + secret + `","note":"x"}}}`,
		"misspelled member case":   `{"Format":"aplane.source-tokens.v1","selector":"` + testKeyID + `","tokens":{` + entry + `}}`,
		"duplicate source":         head + entry + `,` + entry + `}}`,
		"duplicate member":         `{"format":"aplane.source-tokens.v1","format":"aplane.source-tokens.v1","selector":"` + testKeyID + `","tokens":{` + entry + `}}`,
		"whitespace":               head + entry + `} }`,
		"member order":             `{"selector":"` + testKeyID + `","format":"aplane.source-tokens.v1","tokens":{` + entry + `}}`,
		"another format":           strings.Replace(head, "v1", "v2", 1) + entry + `}}`,
		"another selector":         strings.Replace(head, testKeyID, otherTestKeyID, 1) + entry + `}}`,
		"no tokens":                head + `}}`,
		"unicode escape":           head + `"ops":{"set_at":"2026-11-21T10:30:00Z","value":"s3cret\u002dtoken"}}}`,
		"control character":        head + `"ops":{"set_at":"2026-11-21T10:30:00Z","value":"s3cret\ttoken"}}}`,
		"space in token":           head + `"ops":{"set_at":"2026-11-21T10:30:00Z","value":"s3cret token"}}}`,
		"empty token":              head + `"ops":{"set_at":"2026-11-21T10:30:00Z","value":""}}}`,
		"token not a string":       head + `"ops":{"set_at":"2026-11-21T10:30:00Z","value":12345}}}`,
		"fractional set_at":        head + `"ops":{"set_at":"2026-11-21T10:30:00.5Z","value":"` + secret + `"}}}`,
		"offset set_at":            head + `"ops":{"set_at":"2026-11-21T10:30:00+00:00","value":"` + secret + `"}}}`,
		"bad source name":          head + `"Ops":{"set_at":"2026-11-21T10:30:00Z","value":"` + secret + `"}}}`,
		"truncated":                head + entry,
		"trailing data":            head + entry + `}}x`,
		"not json":                 secret,
		"tokens not an object":     head[:len(head)-1] + `"` + secret + `"}`,
		"nine tokens":              head + nineEntries(secret) + `}}`,
		"set_at missing":           head + `"ops":{"value":"` + secret + `"}}}`,
		"token value missing":      head + `"ops":{"set_at":"2026-11-21T10:30:00Z"}}}`,
		"escaped solidus in token": head + `"ops":{"set_at":"2026-11-21T10:30:00Z","value":"s3cret\/token"}}}`,
	}
	for name, plaintext := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := Decode([]byte(plaintext), testKeyID)
			if err == nil {
				t.Fatalf("Decode() accepted %s: %+v", plaintext, f.Listing())
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("Decode() error quotes the token: %v", err)
			}
		})
	}
}

func nineEntries(secret string) string {
	entries := make([]string, MaxTokens+1)
	for i := range entries {
		entries[i] = fmt.Sprintf(`"s%d":{"set_at":"2026-11-21T10:30:00Z","value":"%s"}`, i, secret)
	}
	return strings.Join(entries, ",")
}

func TestSetTokenRules(t *testing.T) {
	full := (*File)(nil)
	for i := range MaxTokens {
		full = mustSet(t, full, testKeyID, fmt.Sprintf("s%d", i), "t")
	}
	long := strings.Repeat("x", MaxTokenBytes)
	refused := errors.New("refused")
	tests := []struct {
		name     string
		current  *File
		selector string
		source   string
		value    []byte
		// wantErr is nil when the set succeeds, refused when any error will
		// do, and a sentinel the error must match otherwise.
		wantErr error
	}{
		{name: "default selector", selector: "default", source: "ops", value: []byte("t")},
		{name: "longest token", selector: testKeyID, source: "ops", value: []byte(long)},
		{name: "every visible ASCII byte", selector: testKeyID, source: "ops", value: visibleASCII()},
		{name: "longest source name", selector: testKeyID, source: strings.Repeat("a", MaxSourceNameBytes), value: []byte("t")},
		{name: "replacing at the cap", current: full, selector: testKeyID, source: "s0", value: []byte("new")},
		{name: "ninth token", current: full, selector: testKeyID, source: "s8", value: []byte("t"), wantErr: ErrTooManyTokens},
		{name: "token too long", selector: testKeyID, source: "ops", value: []byte(long + "x"), wantErr: ErrInvalidToken},
		{name: "empty token", selector: testKeyID, source: "ops", value: nil, wantErr: ErrInvalidToken},
		{name: "space", selector: testKeyID, source: "ops", value: []byte("Bearer x"), wantErr: ErrInvalidToken},
		{name: "newline", selector: testKeyID, source: "ops", value: []byte("x\r\nX-Injected: 1"), wantErr: ErrInvalidToken},
		{name: "DEL", selector: testKeyID, source: "ops", value: []byte("x\x7f"), wantErr: ErrInvalidToken},
		{name: "non-ASCII", selector: testKeyID, source: "ops", value: []byte("tök"), wantErr: ErrInvalidToken},
		{name: "source name too long", selector: testKeyID, source: strings.Repeat("a", MaxSourceNameBytes+1), value: []byte("t"), wantErr: refused},
		{name: "uppercase source name", selector: testKeyID, source: "Ops", value: []byte("t"), wantErr: refused},
		{name: "source name with a leading dash", selector: testKeyID, source: "-ops", value: []byte("t"), wantErr: refused},
		{name: "empty source name", selector: testKeyID, source: "", value: []byte("t"), wantErr: refused},
		{name: "address selector", selector: "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM", source: "ops", value: []byte("t"), wantErr: refused},
		{name: "non-canonical Witness Key ID", selector: testKeyID[:51] + "R", source: "ops", value: []byte("t"), wantErr: refused},
		{name: "another selector's file", current: full, selector: otherTestKeyID, source: "ops", value: []byte("t"), wantErr: refused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := ""
			if tt.current != nil {
				before = string(tt.current.Tokens["s0"].Value)
			}
			next, err := SetToken(tt.current, tt.selector, tt.source, tt.value, testSetAt)
			switch {
			case tt.wantErr == nil:
				if err != nil {
					t.Fatalf("SetToken() error = %v", err)
				}
				if got := next.Tokens[tt.source].Value; !bytes.Equal(got, tt.value) {
					t.Fatalf("token = %q, want %q", got, tt.value)
				}
			case err == nil:
				t.Fatal("SetToken() accepted it")
			case tt.wantErr != refused && !errors.Is(err, tt.wantErr):
				t.Fatalf("SetToken() error = %v, want %v", err, tt.wantErr)
			case len(tt.value) > 1 && strings.Contains(err.Error(), string(tt.value)):
				t.Fatalf("SetToken() error quotes the token: %v", err)
			}
			if tt.current != nil && string(tt.current.Tokens["s0"].Value) != before {
				t.Fatal("SetToken() changed the file it was given")
			}
		})
	}
}

func visibleASCII() []byte {
	out := make([]byte, 0, 0x7e-0x21+1)
	for c := byte(0x21); c <= 0x7e; c++ {
		out = append(out, c)
	}
	return out
}

func TestRemoveTokenDeletesTheFileWithTheLastToken(t *testing.T) {
	f := mustSet(t, nil, testKeyID, "ops", "a")
	f = mustSet(t, f, testKeyID, "screening", "b")
	next, err := RemoveToken(f, "ops")
	if err != nil || next == nil || len(next.Tokens) != 1 || next.Tokens["screening"].Value == nil {
		t.Fatalf("RemoveToken(one of two) = %+v, %v", next.Listing(), err)
	}
	if string(f.Tokens["ops"].Value) != "a" {
		t.Fatal("RemoveToken() changed the file it was given")
	}
	last, err := RemoveToken(next, "screening")
	if err != nil || last != nil {
		t.Fatalf("RemoveToken(last) = %+v, %v; want nil: the file is deleted", last, err)
	}
	for name, current := range map[string]*File{"no file": nil, "another source": next} {
		if _, err := RemoveToken(current, "ops"); !errors.Is(err, ErrTokenNotSet) {
			t.Fatalf("RemoveToken(%s) error = %v, want ErrTokenNotSet", name, err)
		}
	}
}

func TestSealOpenBindsSelectorAndClass(t *testing.T) {
	kr := testKeyring(t)
	f := mustSet(t, nil, testKeyID, "ops", "token-value")
	sealed, err := Seal(f, kr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("token-value")) {
		t.Fatal("sealed file holds the token in the clear")
	}
	opened, err := Open(sealed, testKeyID, kr)
	if err != nil {
		t.Fatalf("Open(own selector) error = %v", err)
	}
	if string(opened.Tokens["ops"].Value) != "token-value" {
		t.Fatalf("opened token = %q", opened.Tokens["ops"].Value)
	}
	// Renamed to another key's file, or to the default's, it does not open.
	for _, selector := range []string{otherTestKeyID, DefaultSelector} {
		if _, err := Open(sealed, selector, kr); err == nil {
			t.Fatalf("Open(%s) opened another selector's file", selector)
		}
	}
	// Sealed as another class with the same selector, it does not open.
	plaintext, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	asCredential, err := kr.Seal(plaintext, crypto.CosignerCredentialContext(testKeyID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(asCredential, testKeyID, kr); err == nil {
		t.Fatal("Open() opened a cosigner credential envelope as source tokens")
	}
	// Under another store's term key it does not open.
	if _, err := Open(sealed, testKeyID, testKeyring(t)); err == nil {
		t.Fatal("Open() opened a file under another keyring")
	}
	if _, err := Open(append(sealed, make([]byte, MaxFileBytes)...), testKeyID, kr); err == nil {
		t.Fatal("Open() accepted a file over the size limit")
	}
}

// A set whose encrypted file would pass MaxFileBytes is refused, and the
// limit reserves room for any later term, so a passphrase change cannot push
// an accepted file over it.
func TestSealRefusesAFileOverTheLimitUnderAnyTerm(t *testing.T) {
	kr := testKeyring(t)
	f := mustSet(t, nil, testKeyID, "s0", strings.Repeat("a", MaxTokenBytes))
	f = mustSet(t, f, testKeyID, "s1", strings.Repeat("b", MaxTokenBytes))
	if _, err := Seal(f, kr); err != nil {
		t.Fatalf("Seal(two long tokens) error = %v", err)
	}
	f = mustSet(t, f, testKeyID, "s2", strings.Repeat("c", MaxTokenBytes))
	_, err := Seal(f, kr)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("Seal(three long tokens) error = %v, want ErrFileTooLarge", err)
	}
	if strings.Contains(err.Error(), "ccc") {
		t.Fatalf("Seal() error quotes a token: %v", err)
	}

	// Find the longest token that still seals at term 1, then seal the same
	// file at the largest term: it stays within the limit.
	base := mustSet(t, nil, testKeyID, "s0", strings.Repeat("a", MaxTokenBytes))
	base = mustSet(t, base, testKeyID, "s1", strings.Repeat("b", MaxTokenBytes))
	var largest *File
	for n := MaxTokenBytes; n > 0; n-- {
		candidate := mustSet(t, base, testKeyID, "s2", strings.Repeat("c", n))
		if _, err := Seal(candidate, kr); err == nil {
			largest = candidate
			break
		}
	}
	if largest == nil {
		t.Fatal("no third token fits")
	}
	late := cryptotest.KeyringAtTerm(t, 1<<62, bytes.Repeat([]byte{0x42}, 32))
	plaintext, err := Encode(largest)
	if err != nil {
		t.Fatal(err)
	}
	sealedLate, err := late.Seal(plaintext, crypto.SourceTokensContext(testKeyID))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealedLate) > MaxFileBytes {
		t.Fatalf("the largest accepted file is %d bytes at a later term, over %d", len(sealedLate), MaxFileBytes)
	}
}

// DecodeSealable accepts exactly the plaintext Seal would seal: a file one
// byte larger than the largest Seal accepts decodes, but is refused as one
// that could not become a token file.
func TestDecodeSealableAcceptsWhatSealAccepts(t *testing.T) {
	kr := testKeyring(t)
	base := mustSet(t, nil, testKeyID, "s0", strings.Repeat("a", MaxTokenBytes))
	base = mustSet(t, base, testKeyID, "s1", strings.Repeat("b", MaxTokenBytes))
	n := MaxTokenBytes
	for ; n > 0; n-- {
		if _, err := Seal(mustSet(t, base, testKeyID, "s2", strings.Repeat("c", n)), kr); err == nil {
			break
		}
	}
	for length, wantErr := range map[int]bool{n: false, n + 1: true} {
		plaintext, err := Encode(mustSet(t, base, testKeyID, "s2", strings.Repeat("c", length)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(plaintext, testKeyID); err != nil {
			t.Fatalf("Decode(token of %d) error = %v", length, err)
		}
		f, err := DecodeSealable(plaintext, testKeyID)
		switch {
		case wantErr && !errors.Is(err, ErrFileTooLarge):
			t.Fatalf("DecodeSealable(token of %d) error = %v, want ErrFileTooLarge", length, err)
		case !wantErr && err != nil:
			t.Fatalf("DecodeSealable(token of %d) error = %v", length, err)
		case err != nil && strings.Contains(err.Error(), "ccc"):
			t.Fatalf("DecodeSealable() error quotes a token: %v", err)
		}
		f.Zero()
	}
	if _, err := DecodeSealable([]byte(`{"format":"aplane.source-tokens.v1"}`), testKeyID); err == nil {
		t.Fatal("DecodeSealable accepted a file Decode refuses")
	}
}
