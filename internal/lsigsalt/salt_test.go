// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigsalt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestIsOnCurve(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	var onCurve [32]byte
	copy(onCurve[:], pub)
	if !IsOnCurve(onCurve) {
		t.Fatal("IsOnCurve(valid Ed25519 public key) = false, want true")
	}

	var offCurve [32]byte
	found := false
	for i := 0; i < 1000; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("off-curve-vector-%d", i)))
		if !IsOnCurve(sum) {
			offCurve = sum
			found = true
			break
		}
	}
	if !found {
		t.Fatal("failed to find deterministic off-curve test vector")
	}
	if IsOnCurve(offCurve) {
		t.Fatal("IsOnCurve(off-curve vector) = true, want false")
	}
}

func TestBytecblockLocator(t *testing.T) {
	bytecode := []byte{0x0c, 0x26, 0x01, 0x01, 0x00, 0x22}
	offset, err := BytecblockLocator(bytecode)
	if err != nil {
		t.Fatalf("BytecblockLocator() error = %v", err)
	}
	if offset != 4 {
		t.Fatalf("BytecblockLocator() = %d, want 4", offset)
	}
}

func TestBytecblockLocatorMultiByteVersion(t *testing.T) {
	// TEAL versions are small today and compile to a one-byte varint. This
	// synthetic bytecode defends the locator's varint handling rather than a
	// currently expected algod output shape.
	bytecode := []byte{0x80, 0x01, 0x26, 0x01, 0x01, 0x00, 0x22}
	offset, err := BytecblockLocator(bytecode)
	if err != nil {
		t.Fatalf("BytecblockLocator() error = %v", err)
	}
	if offset != 5 {
		t.Fatalf("BytecblockLocator() = %d, want 5", offset)
	}
}

func TestBytecblockLocatorMissing(t *testing.T) {
	_, err := BytecblockLocator([]byte{0x26, 0x02, 0x01, 0x00})
	if err == nil {
		t.Fatal("BytecblockLocator() error = nil, want error")
	}
}

func TestBytecblockLocatorRejectsShiftedPattern(t *testing.T) {
	_, err := BytecblockLocator([]byte{0x0c, 0x01, 0x26, 0x01, 0x01, 0x00})
	if err == nil {
		t.Fatal("BytecblockLocator() error = nil, want shifted preamble rejection")
	}
}

func TestBytecblockLocatorRejectsTruncatedVersion(t *testing.T) {
	_, err := BytecblockLocator([]byte{0x80})
	if err == nil {
		t.Fatal("BytecblockLocator() error = nil, want truncated version rejection")
	}
}

func TestBytecblockLocatorRejectsMalformedVersion(t *testing.T) {
	_, err := BytecblockLocator([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02})
	if err == nil {
		t.Fatal("BytecblockLocator() error = nil, want malformed version rejection")
	}
}

func TestPushbytesLocator(t *testing.T) {
	bytecode := compiledPushbytesMarkerBytecode(0x7b)
	offset, err := PushbytesLocator(bytecode)
	if err != nil {
		t.Fatalf("PushbytesLocator() error = %v", err)
	}
	want := 3 + len(pushbytesMarkerPrefix)
	if offset != want {
		t.Fatalf("PushbytesLocator() = %d, want %d", offset, want)
	}
}

func TestPushbytesLocatorMissing(t *testing.T) {
	_, err := PushbytesLocator([]byte{0x0a, 0x80, 0x01, 0x00, 0x48})
	if err == nil {
		t.Fatal("PushbytesLocator() error = nil, want error")
	}
}

func TestPushbytesLocatorRejectsDuplicateMarkers(t *testing.T) {
	bytecode := compiledPushbytesMarkerBytecode(0x00)
	bytecode = append(bytecode, compiledPushbytesMarkerBytecode(0x01)...)

	_, err := PushbytesLocator(bytecode)
	if err == nil {
		t.Fatal("PushbytesLocator() error = nil, want duplicate marker rejection")
	}
}

func TestPushbytesLocatorRejectsTruncatedMarker(t *testing.T) {
	marker := PushbytesSaltMarker(0)
	bytecode := append([]byte{0x0a, 0x80, byte(len(marker))}, marker[:len(marker)-1]...)

	_, err := PushbytesLocator(bytecode)
	if err == nil {
		t.Fatal("PushbytesLocator() error = nil, want truncated marker rejection")
	}
}

func TestPushbytesLocatorIgnoresMalformedUnrelatedPushbytes(t *testing.T) {
	_, err := PushbytesLocator([]byte{0x80, 0x80})
	if err == nil {
		t.Fatal("PushbytesLocator() error = nil, want missing marker error")
	}
}

func TestTrailingBytecblockLocator(t *testing.T) {
	bytecode := []byte{0x0a, 0x81, 0x01, 0x43, 0x26, 0x01, 0x01, 0x7b}
	offset, err := TrailingBytecblockLocator(bytecode)
	if err != nil {
		t.Fatalf("TrailingBytecblockLocator() error = %v", err)
	}
	if offset != len(bytecode)-1 {
		t.Fatalf("TrailingBytecblockLocator() = %d, want %d", offset, len(bytecode)-1)
	}
}

func TestTrailingBytecblockLocatorRejectsMissingTail(t *testing.T) {
	tests := [][]byte{
		{0x0a, 0x26, 0x01, 0x01, 0x00, 0x81, 0x01},
		{0x0a, 0x81, 0x01},
	}
	for _, bytecode := range tests {
		if _, err := TrailingBytecblockLocator(bytecode); err == nil {
			t.Fatalf("TrailingBytecblockLocator(%x) error = nil, want error", bytecode)
		}
	}
}

func TestPushbytesSaltMarkerShape(t *testing.T) {
	marker := PushbytesSaltMarker(0x7b)
	if !bytes.HasPrefix(marker, pushbytesMarkerPrefix) {
		t.Fatalf("PushbytesSaltMarker() missing prefix: %x", marker)
	}
	if !bytes.HasSuffix(marker, pushbytesMarkerSuffix) {
		t.Fatalf("PushbytesSaltMarker() missing suffix: %x", marker)
	}
	if marker[len(pushbytesMarkerPrefix)] != 0x7b {
		t.Fatalf("PushbytesSaltMarker() counter = %x, want 7b", marker[len(pushbytesMarkerPrefix)])
	}
	fixedBytes := len(pushbytesMarkerPrefix) + len(pushbytesMarkerSuffix)
	if fixedBytes < 17 {
		t.Fatalf("PushbytesSaltMarker() fixed bytes = %d, want at least 17", fixedBytes)
	}
}

func TestStyleSourcePreamble(t *testing.T) {
	tests := []struct {
		style Style
		want  string
	}{
		{style: StyleNone, want: ""},
		{style: StyleBytecblock, want: "bytecblock 0x00\n"},
		{style: StylePushbytes, want: "byte 0x" + PushbytesSaltMarkerHex(0) + "\npop\n"},
		{style: StyleTrailingBytecblock, want: ""},
	}

	for _, tt := range tests {
		got, err := tt.style.SourcePreamble()
		if err != nil {
			t.Fatalf("%s.SourcePreamble() error = %v", tt.style, err)
		}
		if got != tt.want {
			t.Fatalf("%s.SourcePreamble() = %q, want %q", tt.style, got, tt.want)
		}
	}

	if _, err := Style("").SourcePreamble(); err == nil {
		t.Fatal("empty style SourcePreamble() error = nil, want error")
	}
	if _, err := Style("bogus").SourcePreamble(); err == nil {
		t.Fatal("unknown style SourcePreamble() error = nil, want error")
	}
}

func TestStyleSourceTrailer(t *testing.T) {
	tests := []struct {
		style Style
		want  string
	}{
		{style: StyleNone, want: ""},
		{style: StyleBytecblock, want: ""},
		{style: StylePushbytes, want: ""},
		{style: StyleTrailingBytecblock, want: "bytecblock 0x00\n"},
	}

	for _, tt := range tests {
		got, err := tt.style.SourceTrailer()
		if err != nil {
			t.Fatalf("%s.SourceTrailer() error = %v", tt.style, err)
		}
		if got != tt.want {
			t.Fatalf("%s.SourceTrailer() = %q, want %q", tt.style, got, tt.want)
		}
	}

	if _, err := Style("").SourceTrailer(); err == nil {
		t.Fatal("empty style SourceTrailer() error = nil, want error")
	}
	if _, err := Style("bogus").SourceTrailer(); err == nil {
		t.Fatal("unknown style SourceTrailer() error = nil, want error")
	}
}

func TestStyleLocator(t *testing.T) {
	tests := []struct {
		style    Style
		bytecode []byte
		want     int
	}{
		{style: StyleBytecblock, bytecode: []byte{0x0c, 0x26, 0x01, 0x01, 0x00, 0x22}, want: 4},
		{style: StylePushbytes, bytecode: compiledPushbytesMarkerBytecode(0x7b), want: 3 + len(pushbytesMarkerPrefix)},
		{style: StyleTrailingBytecblock, bytecode: []byte{0x0c, 0x81, 0x01, 0x26, 0x01, 0x01, 0x7b}, want: 6},
	}

	for _, tt := range tests {
		locate, err := tt.style.Locator()
		if err != nil {
			t.Fatalf("%s.Locator() error = %v", tt.style, err)
		}
		got, err := locate(tt.bytecode)
		if err != nil {
			t.Fatalf("%s locator error = %v", tt.style, err)
		}
		if got != tt.want {
			t.Fatalf("%s locator = %d, want %d", tt.style, got, tt.want)
		}
	}

	if _, err := Style("").Locator(); err == nil {
		t.Fatal("empty style Locator() error = nil, want error")
	}
	if _, err := Style("bogus").Locator(); err == nil {
		t.Fatal("unknown style Locator() error = nil, want error")
	}
	if _, err := StyleNone.Locator(); err == nil {
		t.Fatal("none style Locator() error = nil, want error")
	}
}

func compiledPushbytesMarkerBytecode(counter byte) []byte {
	marker := PushbytesSaltMarker(counter)
	bytecode := []byte{0x0a, 0x80, byte(len(marker))}
	bytecode = append(bytecode, marker...)
	bytecode = append(bytecode, 0x48, 0x81, 0x01)
	return bytecode
}

func TestCounterFromBytecode(t *testing.T) {
	bytecode := []byte{0x0c, 0x26, 0x01, 0x01, 0x7b, 0x81, 0x01}
	counter, err := CounterFromBytecode(bytecode, BytecblockLocator)
	if err != nil {
		t.Fatalf("CounterFromBytecode() error = %v", err)
	}
	if counter != 0x7b {
		t.Fatalf("CounterFromBytecode() = %d, want %d", counter, 0x7b)
	}
}

func TestFindOffCurve(t *testing.T) {
	bytecode := []byte{0x0c, 0x26, 0x01, 0x01, 0x00, 0x81, 0x01}
	original := append([]byte(nil), bytecode...)

	result, err := FindOffCurve(bytecode, BytecblockLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() error = %v", err)
	}
	if IsOnCurve(result.Address) {
		t.Fatal("FindOffCurve() returned on-curve address")
	}
	if len(result.Bytecode) != len(bytecode) {
		t.Fatalf("patched bytecode length = %d, want %d", len(result.Bytecode), len(bytecode))
	}
	if result.Bytecode[4] != result.Counter {
		t.Fatalf("patched counter byte = %d, want %d", result.Bytecode[4], result.Counter)
	}
	if !bytes.Equal(bytecode, original) {
		t.Fatalf("FindOffCurve mutated input: got %x want %x", bytecode, original)
	}

	result2, err := FindOffCurve(bytecode, BytecblockLocator)
	if err != nil {
		t.Fatalf("FindOffCurve() second call error = %v", err)
	}
	if !bytes.Equal(result.Bytecode, result2.Bytecode) || result.Address != result2.Address || result.Counter != result2.Counter {
		t.Fatalf("FindOffCurve() not deterministic:\nfirst:  %+v\nsecond: %+v", result, result2)
	}
}

func TestUseUnmodifiedOffCurve(t *testing.T) {
	bytecode := []byte{0x0a, 0x81, 0x00}
	for counter := 0; counter < MaxIterations; counter++ {
		bytecode[2] = byte(counter)
		result, err := UseUnmodifiedOffCurve(bytecode)
		if err == nil {
			if !bytes.Equal(result.Bytecode, bytecode) {
				t.Fatalf("UseUnmodifiedOffCurve() bytecode = %x, want %x", result.Bytecode, bytecode)
			}
			if result.Counter != 0 {
				t.Fatalf("UseUnmodifiedOffCurve() counter = %d, want 0", result.Counter)
			}
			if IsOnCurve(result.Address) {
				t.Fatal("UseUnmodifiedOffCurve() returned on-curve address")
			}
			return
		}
		if !errors.Is(err, ErrUnsaltedAddressOnCurve) {
			t.Fatalf("UseUnmodifiedOffCurve() error = %v, want nil or %v", err, ErrUnsaltedAddressOnCurve)
		}
	}
	t.Fatal("failed to find deterministic off-curve bytecode for test")
}

func TestFindOffCurveAtOffset(t *testing.T) {
	bytecode := []byte{0x01, 0x02, 0x00, 0x04}
	original := append([]byte(nil), bytecode...)

	result, err := FindOffCurveAtOffset(bytecode, 2)
	if err != nil {
		t.Fatalf("FindOffCurveAtOffset() error = %v", err)
	}
	if IsOnCurve(result.Address) {
		t.Fatal("FindOffCurveAtOffset() returned on-curve address")
	}
	if len(result.Bytecode) != len(bytecode) {
		t.Fatalf("patched bytecode length = %d, want %d", len(result.Bytecode), len(bytecode))
	}
	if result.Bytecode[2] != result.Counter {
		t.Fatalf("patched counter byte = %d, want %d", result.Bytecode[2], result.Counter)
	}
	for i := range result.Bytecode {
		if i == 2 {
			continue
		}
		if result.Bytecode[i] != bytecode[i] {
			t.Fatalf("byte at offset %d changed: got %x want %x", i, result.Bytecode[i], bytecode[i])
		}
	}
	if !bytes.Equal(bytecode, original) {
		t.Fatalf("FindOffCurveAtOffset mutated input: got %x want %x", bytecode, original)
	}
}

func TestFindOffCurveAtOffsetOutOfRange(t *testing.T) {
	for _, offset := range []int{-1, 1} {
		_, err := FindOffCurveAtOffset([]byte{0x00}, offset)
		if err == nil {
			t.Fatalf("FindOffCurveAtOffset(offset=%d) error = nil, want error", offset)
		}
	}
}

func TestFindOffCurveLocatorErrors(t *testing.T) {
	_, err := FindOffCurve([]byte{0x01}, nil)
	if err == nil {
		t.Fatal("FindOffCurve(nil locator) error = nil, want error")
	}

	_, err = FindOffCurve([]byte{0x01}, func([]byte) (int, error) { return 2, nil })
	if err == nil {
		t.Fatal("FindOffCurve(out-of-range locator) error = nil, want error")
	}

	wantErr := errors.New("locator failed")
	_, err = FindOffCurve([]byte{0x01}, func([]byte) (int, error) { return 0, wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("FindOffCurve(locator error) = %v, want %v", err, wantErr)
	}
}

func TestFindOffCurveNoSuitableCounter(t *testing.T) {
	bytecode := []byte{0x00}
	deriveOnCurve := func([]byte) (types.Address, error) {
		pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		var addr types.Address
		copy(addr[:], pub)
		return addr, nil
	}

	_, err := findOffCurveAtOffset(bytecode, 0, deriveOnCurve)
	if !errors.Is(err, ErrNoSuitableCounter) {
		t.Fatalf("findOffCurveAtOffset() error = %v, want %v", err, ErrNoSuitableCounter)
	}
}
