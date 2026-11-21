// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package sourcetokens owns a cosigner's source tokens: the tokens its
// policy documents' external sources authenticate with. One encrypted file
// per policy selector holds that selector's tokens by source name, in the
// selected generation's source_tokens/ namespace. This package defines the
// file's plaintext schema (aplane.source-tokens.v1), its limits, how it is
// sealed under the store's term and read and written in a generation, and
// the immutable runtime index the external checks read tokens from.
//
// No function here returns a token value in an error, and none logs one.
package sourcetokens

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	// Format names the plaintext schema of a source token file.
	Format = "aplane.source-tokens.v1"
	// DefaultSelector names the node default document's token file.
	DefaultSelector = storepaths.SourceTokensDefaultSelector
	// MaxTokens is the most tokens one selector holds.
	MaxTokens = 8
	// MaxSourceNameBytes is the longest source name, as policy documents
	// allow it.
	MaxSourceNameBytes = policy.MaxExternalSourceName
	// MaxTokenBytes is the longest token.
	MaxTokenBytes = 1024
	// MaxFileBytes is the largest encrypted token file. It keeps token files
	// within the supported store size: at 8,192 keys they take at most
	// 32 MiB. Eight tokens fit only when they are short.
	MaxFileBytes = 4096
)

var (
	// ErrFileTooLarge refuses a change whose encrypted file would exceed
	// MaxFileBytes.
	ErrFileTooLarge = errors.New("source token file would exceed its size limit")
	// ErrTooManyTokens refuses a token past MaxTokens for one selector.
	ErrTooManyTokens = errors.New("source token limit reached")
	// ErrTokenNotSet reports a source with no token.
	ErrTokenNotSet = errors.New("no token is set for this source")
	// ErrInvalidToken refuses a token outside the token rules.
	ErrInvalidToken = errors.New("invalid source token")
)

// Token is one source's token and when it was set.
type Token struct {
	// Value is the token, 1 to MaxTokenBytes of visible ASCII. It is owned
	// by the File that holds it and zeroed with it.
	Value []byte
	// SetAt is when the token was set, in UTC to the second.
	SetAt time.Time
}

// File is one selector's decoded token file.
type File struct {
	Selector string
	// Tokens maps a source name to its token.
	Tokens map[string]Token
}

// Entry describes one token without its value.
type Entry struct {
	Source string
	SetAt  time.Time
}

// Listing returns the file's tokens by source name, sorted, without values.
// A nil file lists nothing.
func (f *File) Listing() []Entry {
	if f == nil {
		return nil
	}
	out := make([]Entry, 0, len(f.Tokens))
	for _, source := range slices.Sorted(maps.Keys(f.Tokens)) {
		out = append(out, Entry{Source: source, SetAt: f.Tokens[source].SetAt})
	}
	return out
}

// Zero clears every token value the file holds. A nil file is a no-op.
func (f *File) Zero() {
	if f == nil {
		return
	}
	for _, token := range f.Tokens {
		crypto.ZeroBytes(token.Value)
	}
}

// clone deep-copies the file, so the copy owns its own token bytes.
func (f *File) clone() *File {
	out := &File{Selector: f.Selector, Tokens: make(map[string]Token, len(f.Tokens))}
	for source, token := range f.Tokens {
		out.Tokens[source] = Token{Value: bytes.Clone(token.Value), SetAt: token.SetAt}
	}
	return out
}

// ValidateSelector reports whether selector may hold source tokens: the
// node default ("default") or a canonical Witness Key ID.
func ValidateSelector(selector string) error {
	if err := storepaths.ValidateSourceTokenSelector(selector); err != nil {
		return err
	}
	if selector == DefaultSelector {
		return nil
	}
	if canonical, err := witness.NormalizeID(selector); err != nil || canonical != selector {
		return fmt.Errorf("invalid source token selector %q: not a canonical Witness Key ID", selector)
	}
	return nil
}

// ValidateSourceName reports whether name is a valid source name, by the
// policy document's own rule (policy.IsExternalSourceName).
func ValidateSourceName(name string) error {
	if !policy.IsExternalSourceName(name) {
		return fmt.Errorf("source name %q must be 1 to %d lowercase letters, digits, '_' or '-', starting with a letter or digit",
			name, MaxSourceNameBytes)
	}
	return nil
}

// ValidateTokenValue reports whether value is a valid token: 1 to
// MaxTokenBytes bytes of visible ASCII (0x21 to 0x7E), so no space, CR or LF
// can reach a request header. The error never contains the value.
func ValidateTokenValue(value []byte) error {
	if len(value) == 0 || len(value) > MaxTokenBytes {
		return fmt.Errorf("%w: a token is 1 to %d bytes, got %d", ErrInvalidToken, MaxTokenBytes, len(value))
	}
	for i, c := range value {
		if c < 0x21 || c > 0x7e {
			return fmt.Errorf("%w: byte %d is not visible ASCII", ErrInvalidToken, i+1)
		}
	}
	return nil
}

// SetToken returns a copy of current with value set as source's token at
// setAt, replacing any token source had. current may be nil when selector has
// no file yet. The copy owns its own token bytes: the caller still zeroes
// value and current. It does not check the encrypted size, which only
// sealing knows; Seal does.
func SetToken(current *File, selector, source string, value []byte, setAt time.Time) (*File, error) {
	if err := ValidateSelector(selector); err != nil {
		return nil, err
	}
	if current != nil && current.Selector != selector {
		return nil, fmt.Errorf("source token file of %s cannot take a token for %s", current.Selector, selector)
	}
	if err := ValidateSourceName(source); err != nil {
		return nil, err
	}
	if err := ValidateTokenValue(value); err != nil {
		return nil, err
	}
	next := &File{Selector: selector, Tokens: map[string]Token{}}
	if current != nil {
		next = current.clone()
	}
	if _, replaced := next.Tokens[source]; !replaced && len(next.Tokens) >= MaxTokens {
		next.Zero()
		return nil, fmt.Errorf("%w: %s already has %d tokens", ErrTooManyTokens, selector, MaxTokens)
	}
	if old, ok := next.Tokens[source]; ok {
		crypto.ZeroBytes(old.Value)
	}
	next.Tokens[source] = Token{Value: bytes.Clone(value), SetAt: setAt.UTC().Truncate(time.Second)}
	return next, nil
}

// RemoveToken returns a copy of current without source's token. It returns
// nil when that was the file's last token: the file is then deleted, never
// archived. The caller still zeroes current.
func RemoveToken(current *File, source string) (*File, error) {
	if current == nil {
		return nil, ErrTokenNotSet
	}
	if _, ok := current.Tokens[source]; !ok {
		return nil, fmt.Errorf("%w: %s has no token for source %q", ErrTokenNotSet, current.Selector, source)
	}
	if len(current.Tokens) == 1 {
		return nil, nil
	}
	next := current.clone()
	crypto.ZeroBytes(next.Tokens[source].Value)
	delete(next.Tokens, source)
	return next, nil
}

// Seal encodes f and encrypts it under the keyring's current term, bound to
// f's selector. It refuses a file whose envelope would exceed MaxFileBytes
// under any later term, so a passphrase change, which re-encrypts the file
// under a new term, never pushes it over the limit.
func Seal(f *File, kr *crypto.Keyring) ([]byte, error) {
	plaintext, err := Encode(f)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(plaintext)
	if err := checkSealedSize(f.Selector, len(plaintext)); err != nil {
		return nil, err
	}
	sealed, err := kr.Seal(plaintext, crypto.SourceTokensContext(f.Selector))
	if err != nil {
		return nil, fmt.Errorf("encrypt source tokens of %s: %w", f.Selector, err)
	}
	return sealed, nil
}

// checkSealedSize refuses plaintext whose token file would exceed
// MaxFileBytes under some term. The term is the only part of an envelope
// whose length can change when the same plaintext is sealed again, so the
// bound is taken at the longest term an envelope can carry.
func checkSealedSize(selector string, plaintextLen int) error {
	if size := crypto.TermEnvelopeLen(plaintextLen, math.MaxInt64); size > MaxFileBytes {
		return fmt.Errorf("%w: the tokens of %s would take %d encrypted bytes, more than %d; use fewer or shorter tokens",
			ErrFileTooLarge, selector, size, MaxFileBytes)
	}
	return nil
}

// DecodeSealable is Decode for plaintext that is to become selector's token
// file, as a backup carries it: it must also be small enough to seal within
// MaxFileBytes under any term. The caller zeroes plaintext and the file.
func DecodeSealable(plaintext []byte, selector string) (*File, error) {
	f, err := Decode(plaintext, selector)
	if err != nil {
		return nil, err
	}
	if err := checkSealedSize(selector, len(plaintext)); err != nil {
		f.Zero()
		return nil, err
	}
	return f, nil
}

// Open decrypts one token file as selector's and decodes it. The file must
// be within MaxFileBytes, open under selector's object context (a file
// renamed to another selector fails here), and hold the schema exactly.
func Open(sealed []byte, selector string, kr *crypto.Keyring) (*File, error) {
	if err := ValidateSelector(selector); err != nil {
		return nil, err
	}
	if len(sealed) > MaxFileBytes {
		return nil, fmt.Errorf("source tokens of %s: file is %d bytes, more than %d", selector, len(sealed), MaxFileBytes)
	}
	plaintext, err := kr.Open(sealed, crypto.SourceTokensContext(selector))
	if err != nil {
		return nil, fmt.Errorf("source tokens of %s: %w", selector, err)
	}
	defer crypto.ZeroBytes(plaintext)
	return Decode(plaintext, selector)
}

// Encode returns f's canonical plaintext: compact JSON with members in a
// fixed order, sources sorted, and a token's only escapes \" and \\. The
// caller zeroes the result. It is built in one buffer of its exact size, so
// no partial copy of a token is left behind.
func Encode(f *File) ([]byte, error) {
	if err := validateFile(f); err != nil {
		return nil, err
	}
	sources := slices.Sorted(maps.Keys(f.Tokens))
	head := `{"format":"` + Format + `","selector":"` + f.Selector + `","tokens":{`
	size := len(head) + len("}}")
	for i, source := range sources {
		token := f.Tokens[source]
		size += len(tokenHead(source, token.SetAt)) + escapedLen(token.Value) + len(`"}`)
		if i > 0 {
			size++
		}
	}
	out := make([]byte, 0, size)
	out = append(out, head...)
	for i, source := range sources {
		if i > 0 {
			out = append(out, ',')
		}
		token := f.Tokens[source]
		out = append(out, tokenHead(source, token.SetAt)...)
		out = appendEscaped(out, token.Value)
		out = append(out, `"}`...)
	}
	return append(out, "}}"...), nil
}

func tokenHead(source string, setAt time.Time) string {
	return `"` + source + `":{"set_at":"` + setAt.UTC().Format(time.RFC3339) + `","value":"`
}

func escapedLen(value []byte) int {
	n := len(value)
	for _, c := range value {
		if c == '"' || c == '\\' {
			n++
		}
	}
	return n
}

func appendEscaped(out, value []byte) []byte {
	for _, c := range value {
		if c == '"' || c == '\\' {
			out = append(out, '\\')
		}
		out = append(out, c)
	}
	return out
}

// Decode reads canonical plaintext as selector's token file. Anything Encode
// would not have written is refused: an unknown or misspelled member, a
// duplicate, another order, whitespace, an escape other than \" and \\. The
// caller zeroes plaintext; the returned file owns copies of the tokens.
func Decode(plaintext []byte, selector string) (*File, error) {
	var w wireFile
	defer w.zero()
	// json.Unmarshal, not a Decoder: a Decoder copies the input into a
	// buffer of its own, which would keep the tokens out of reach of the
	// zeroing above.
	if err := json.Unmarshal(plaintext, &w); err != nil {
		return nil, fmt.Errorf("source tokens of %s: %s", selector, describeJSONError(err))
	}
	if w.Format != Format {
		return nil, fmt.Errorf("source tokens of %s: format %q is not %s", selector, w.Format, Format)
	}
	if w.Selector != selector {
		return nil, fmt.Errorf("source tokens of %s: the file says it holds the tokens of %q", selector, w.Selector)
	}
	f := &File{Selector: selector, Tokens: make(map[string]Token, len(w.Tokens))}
	for source, wt := range w.Tokens {
		token, err := wt.decode(source)
		if err != nil {
			f.Zero()
			return nil, fmt.Errorf("source tokens of %s: %w", selector, err)
		}
		f.Tokens[source] = token
	}
	canonical, err := Encode(f)
	if err != nil {
		f.Zero()
		return nil, fmt.Errorf("source tokens of %s: %w", selector, err)
	}
	defer crypto.ZeroBytes(canonical)
	if !bytes.Equal(canonical, plaintext) {
		f.Zero()
		return nil, fmt.Errorf("source tokens of %s: the file is not in canonical form", selector)
	}
	return f, nil
}

// validateFile checks a whole file against the schema's rules.
func validateFile(f *File) error {
	if f == nil {
		return fmt.Errorf("source token file is nil")
	}
	if err := ValidateSelector(f.Selector); err != nil {
		return err
	}
	if len(f.Tokens) == 0 {
		return fmt.Errorf("the source token file of %s holds no token; a selector without tokens has no file", f.Selector)
	}
	if len(f.Tokens) > MaxTokens {
		return fmt.Errorf("%w: %s holds %d tokens, more than %d", ErrTooManyTokens, f.Selector, len(f.Tokens), MaxTokens)
	}
	for source, token := range f.Tokens {
		if err := ValidateSourceName(source); err != nil {
			return err
		}
		if err := ValidateTokenValue(token.Value); err != nil {
			return fmt.Errorf("source %q: %w", source, err)
		}
		if token.SetAt.IsZero() || !token.SetAt.Equal(token.SetAt.UTC().Truncate(time.Second)) {
			return fmt.Errorf("source %q: set_at must be a time to the second", source)
		}
	}
	return nil
}

// describeJSONError says where JSON decoding failed without quoting the
// input, which may hold a token.
func describeJSONError(err error) string {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return fmt.Sprintf("malformed JSON at byte %d", syntax.Offset)
	case errors.As(err, &typeErr):
		return fmt.Sprintf("%s has the wrong type (%s)", typeErr.Field, typeErr.Value)
	case errors.Is(err, ErrInvalidToken):
		return err.Error()
	default:
		return "malformed JSON"
	}
}

type wireFile struct {
	Format   string               `json:"format"`
	Selector string               `json:"selector"`
	Tokens   map[string]wireToken `json:"tokens"`
}

type wireToken struct {
	SetAt string      `json:"set_at"`
	Value secretValue `json:"value"`
}

func (w *wireFile) zero() {
	for _, token := range w.Tokens {
		crypto.ZeroBytes(token.Value)
	}
}

func (w wireToken) decode(source string) (Token, error) {
	setAt, err := time.Parse(time.RFC3339, w.SetAt)
	if err != nil || setAt.Location() != time.UTC || setAt.Format(time.RFC3339) != w.SetAt {
		return Token{}, fmt.Errorf("source %q: set_at %q is not an RFC 3339 UTC time to the second", source, w.SetAt)
	}
	value, err := w.Value.unescape()
	if err != nil {
		return Token{}, fmt.Errorf("source %q: %w", source, err)
	}
	return Token{Value: value, SetAt: setAt}, nil
}

// secretValue is a token's JSON string as the decoder read it, quotes and
// escapes included, held in a buffer this package owns, so the token never
// becomes a Go string and can be zeroed once it is decoded.
type secretValue []byte

// UnmarshalJSON keeps a copy of a string literal. Anything else is refused
// without quoting it.
func (v *secretValue) UnmarshalJSON(data []byte) error {
	crypto.ZeroBytes(*v)
	*v = nil
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("%w: a token must be a JSON string", ErrInvalidToken)
	}
	*v = append(secretValue(nil), data...)
	return nil
}

// unescape returns the token the literal encodes, accepting only the escapes
// Encode writes.
func (v secretValue) unescape() ([]byte, error) {
	if len(v) < 2 {
		return nil, fmt.Errorf("%w: a token must be a JSON string", ErrInvalidToken)
	}
	body := v[1 : len(v)-1]
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == '\\' {
			if i+1 == len(body) || (body[i+1] != '"' && body[i+1] != '\\') {
				crypto.ZeroBytes(out)
				return nil, fmt.Errorf("%w: only \\\" and \\\\ may be escaped in a token", ErrInvalidToken)
			}
			i++
			c = body[i]
		}
		out = append(out, c)
	}
	if err := ValidateTokenValue(out); err != nil {
		crypto.ZeroBytes(out)
		return nil, err
	}
	return out, nil
}
