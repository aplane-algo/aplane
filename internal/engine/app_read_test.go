// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
)

func TestReadAppGlobalState_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := eng.ReadAppGlobalState(context.Background(), 123)
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestReadAppInfo_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := eng.ReadAppInfo(context.Background(), 123)
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestReadAppLocalState_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := eng.ReadAppLocalState(context.Background(), testAddress(1).String(), 123)
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestReadAppBox_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := eng.ReadAppBox(context.Background(), 123, []byte("box"))
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestListAppBoxes_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := eng.ListAppBoxes(context.Background(), 123)
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestNormalizeStateEntries(t *testing.T) {
	counterKey := base64.StdEncoding.EncodeToString([]byte("counter"))
	rawKey := base64.StdEncoding.EncodeToString([]byte{0xff, 0x00})
	helloValue := base64.StdEncoding.EncodeToString([]byte("hello"))

	entries := normalizeStateEntries([]models.TealKeyValue{
		{
			Key: rawKey,
			Value: models.TealValue{
				Type: 2,
				Uint: 7,
			},
		},
		{
			Key: counterKey,
			Value: models.TealValue{
				Type:  1,
				Bytes: helloValue,
			},
		},
	})

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].KeyBase64 > entries[1].KeyBase64 {
		t.Fatalf("expected entries sorted by key, got %q then %q", entries[0].KeyBase64, entries[1].KeyBase64)
	}
	var counterEntry, rawEntry AppStateEntry
	if entries[0].KeyBase64 == counterKey {
		counterEntry = entries[0]
		rawEntry = entries[1]
	} else {
		counterEntry = entries[1]
		rawEntry = entries[0]
	}
	if counterEntry.KeyText != "counter" {
		t.Fatalf("expected decoded text key, got %q", counterEntry.KeyText)
	}
	if counterEntry.Value.Type != "bytes" {
		t.Fatalf("expected bytes value type, got %q", counterEntry.Value.Type)
	}
	if counterEntry.Value.BytesText != "hello" {
		t.Fatalf("expected decoded bytes text, got %q", counterEntry.Value.BytesText)
	}

	if rawEntry.KeyBase64 != rawKey {
		t.Fatalf("expected raw key entry, got %q", rawEntry.KeyBase64)
	}
	if rawEntry.KeyText != "" {
		t.Fatalf("expected non-UTF8 key text to be omitted, got %q", rawEntry.KeyText)
	}
	if rawEntry.Value.Type != "uint" || rawEntry.Value.Uint != 7 {
		t.Fatalf("unexpected uint value: %+v", rawEntry.Value)
	}
}

func TestPrintableText(t *testing.T) {
	if got := printableText([]byte("user_1")); got != "user_1" {
		t.Fatalf("expected printable text, got %q", got)
	}
	if got := printableText([]byte{0xff, 0x00}); got != "" {
		t.Fatalf("expected invalid utf8 to be omitted, got %q", got)
	}
}
