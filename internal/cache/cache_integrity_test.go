// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

type testVersionedCachePayload struct {
	SchemaVersion int    `json:"schema_version,omitempty"`
	Value         string `json:"value"`
}

func (p *testVersionedCachePayload) cachePayloadSchemaVersion() int {
	return p.SchemaVersion
}

func (p *testVersionedCachePayload) setCachePayloadSchemaVersion(version int) {
	p.SchemaVersion = version
}

func TestGetOrCreateCacheKeyPersistsPerStore(t *testing.T) {
	store := NewStore(t.TempDir())

	key1, err := getOrCreateCacheKey(store)
	if err != nil {
		t.Fatalf("getOrCreateCacheKey() first call error = %v", err)
	}
	key2, err := getOrCreateCacheKey(store)
	if err != nil {
		t.Fatalf("getOrCreateCacheKey() second call error = %v", err)
	}

	if len(key1) != 32 {
		t.Fatalf("len(key1) = %d, want 32", len(key1))
	}
	if string(key1) != string(key2) {
		t.Fatal("cache key changed between loads")
	}
}

func TestGetOrCreateCacheKeyConcurrentBootstrapUsesSingleKey(t *testing.T) {
	store := NewStore(t.TempDir())
	const workers = 32

	start := make(chan struct{})
	keys := make([][]byte, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			keys[i], errs[i] = getOrCreateCacheKey(store)
		}(i)
	}

	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d getOrCreateCacheKey() error = %v", i, err)
		}
	}
	for i := 1; i < workers; i++ {
		if !bytes.Equal(keys[0], keys[i]) {
			t.Fatalf("worker %d key differs from worker 0", i)
		}
	}
	diskKey, err := os.ReadFile(storePath(store, ".cache_key"))
	if err != nil {
		t.Fatalf("ReadFile(.cache_key) error = %v", err)
	}
	if !bytes.Equal(keys[0], diskKey) {
		t.Fatal("returned key differs from persisted cache key")
	}
}

func TestCreateCacheKeyFileAtomicallyDoesNotOverwriteExistingKey(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := os.MkdirAll(cacheDir(store), 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	keyFile := storePath(store, ".cache_key")
	existing := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(keyFile, existing, 0o600); err != nil {
		t.Fatalf("WriteFile(.cache_key) error = %v", err)
	}

	created, err := createCacheKeyFileAtomically(keyFile, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatalf("createCacheKeyFileAtomically() error = %v", err)
	}
	if created {
		t.Fatal("createCacheKeyFileAtomically() created = true, want existing key preserved")
	}
	got, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("ReadFile(.cache_key) error = %v", err)
	}
	if !bytes.Equal(got, existing) {
		t.Fatal("existing cache key was overwritten")
	}
}

func TestGetOrCreateCacheKeyRejectsInvalidLength(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := os.MkdirAll(cacheDir(store), 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(storePath(store, ".cache_key"), []byte("short"), 0o600); err != nil {
		t.Fatalf("WriteFile(.cache_key) error = %v", err)
	}

	_, err := getOrCreateCacheKey(store)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid cache key length") {
		t.Fatalf("error = %q, want invalid cache key length", err.Error())
	}
}

func TestSaveAndLoadSignedCacheRoundTrip(t *testing.T) {
	store := NewStore(t.TempDir())
	filename := storePath(store, "roundtrip.json")

	key, err := getOrCreateCacheKey(store)
	if err != nil {
		t.Fatalf("getOrCreateCacheKey() error = %v", err)
	}

	payload := map[string]any{
		"keys": []string{"ADDR1", "ADDR2"},
		"flag": true,
	}
	if err := SaveSignedCache(filename, payload, key); err != nil {
		t.Fatalf("SaveSignedCache() error = %v", err)
	}

	var loaded map[string]any
	if err := LoadSignedCache(filename, key, &loaded); err != nil {
		t.Fatalf("LoadSignedCache() error = %v", err)
	}
	if loaded["flag"] != true {
		t.Fatalf("loaded flag = %#v, want true", loaded["flag"])
	}
	gotKeys, ok := loaded["keys"].([]any)
	if !ok || len(gotKeys) != 2 {
		t.Fatalf("loaded keys = %#v, want 2 entries", loaded["keys"])
	}
}

func TestSaveSignedCacheWritesPayloadSchemaVersion(t *testing.T) {
	store := NewStore(t.TempDir())
	filename := storePath(store, "versioned.json")

	key, err := getOrCreateCacheKey(store)
	if err != nil {
		t.Fatalf("getOrCreateCacheKey() error = %v", err)
	}

	payload := &testVersionedCachePayload{Value: "ok"}
	if err := SaveSignedCache(filename, payload, key); err != nil {
		t.Fatalf("SaveSignedCache() error = %v", err)
	}
	if payload.SchemaVersion != cachePayloadSchemaVersion {
		t.Fatalf("payload.SchemaVersion = %d, want %d", payload.SchemaVersion, cachePayloadSchemaVersion)
	}

	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", filename, err)
	}
	var signed SignedCache
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatalf("json.Unmarshal(signed cache) error = %v", err)
	}
	if signed.Version != signedCacheEnvelopeVersion {
		t.Fatalf("signed.Version = %d, want %d", signed.Version, signedCacheEnvelopeVersion)
	}

	dataBytes, err := base64.StdEncoding.DecodeString(signed.Data)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	var decoded testVersionedCachePayload
	if err := json.Unmarshal(dataBytes, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	if decoded.SchemaVersion != cachePayloadSchemaVersion {
		t.Fatalf("decoded.SchemaVersion = %d, want %d", decoded.SchemaVersion, cachePayloadSchemaVersion)
	}
}

func TestLoadSignedCacheDefaultsLegacyPayloadSchemaVersion(t *testing.T) {
	store := NewStore(t.TempDir())
	filename := storePath(store, "legacy-versioned.json")

	key, err := getOrCreateCacheKey(store)
	if err != nil {
		t.Fatalf("getOrCreateCacheKey() error = %v", err)
	}
	payloadBytes := []byte(`{"value":"legacy"}`)
	signed := SignedCache{
		Version: signedCacheEnvelopeVersion,
		Data:    base64.StdEncoding.EncodeToString(payloadBytes),
		HMAC:    signCacheData(payloadBytes, key),
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal(signed cache) error = %v", err)
	}
	if err := os.WriteFile(filename, raw, 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filename, err)
	}

	var loaded testVersionedCachePayload
	if err := LoadSignedCache(filename, key, &loaded); err != nil {
		t.Fatalf("LoadSignedCache() error = %v", err)
	}
	if loaded.Value != "legacy" {
		t.Fatalf("loaded.Value = %q, want legacy", loaded.Value)
	}
	if loaded.SchemaVersion != cachePayloadSchemaVersion {
		t.Fatalf("loaded.SchemaVersion = %d, want %d", loaded.SchemaVersion, cachePayloadSchemaVersion)
	}
}

func TestLoadSignedCacheRejectsUnsupportedEnvelopeVersion(t *testing.T) {
	store := NewStore(t.TempDir())
	filename := storePath(store, "future-envelope.json")

	key, err := getOrCreateCacheKey(store)
	if err != nil {
		t.Fatalf("getOrCreateCacheKey() error = %v", err)
	}
	payloadBytes := []byte(`{"value":"future"}`)
	signed := SignedCache{
		Version: signedCacheEnvelopeVersion + 1,
		Data:    base64.StdEncoding.EncodeToString(payloadBytes),
		HMAC:    signCacheData(payloadBytes, key),
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal(signed cache) error = %v", err)
	}
	if err := os.WriteFile(filename, raw, 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filename, err)
	}

	var loaded testVersionedCachePayload
	err = LoadSignedCache(filename, key, &loaded)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported cache envelope version") {
		t.Fatalf("error = %q, want unsupported cache envelope version", err.Error())
	}
}

func TestLoadSignedCacheRejectsUnsupportedPayloadSchemaVersion(t *testing.T) {
	store := NewStore(t.TempDir())
	filename := storePath(store, "future-payload.json")

	key, err := getOrCreateCacheKey(store)
	if err != nil {
		t.Fatalf("getOrCreateCacheKey() error = %v", err)
	}
	payloadBytes := []byte(`{"schema_version":2,"value":"future"}`)
	signed := SignedCache{
		Version: signedCacheEnvelopeVersion,
		Data:    base64.StdEncoding.EncodeToString(payloadBytes),
		HMAC:    signCacheData(payloadBytes, key),
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal(signed cache) error = %v", err)
	}
	if err := os.WriteFile(filename, raw, 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filename, err)
	}

	var loaded testVersionedCachePayload
	err = LoadSignedCache(filename, key, &loaded)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported cache payload schema_version") {
		t.Fatalf("error = %q, want unsupported cache payload schema_version", err.Error())
	}
	if loaded.Value != "" {
		t.Fatalf("loaded.Value = %q, want empty after rejected payload", loaded.Value)
	}
}

func TestLoadSignedCacheRejectsTampering(t *testing.T) {
	store := NewStore(t.TempDir())
	filename := storePath(store, "tampered.json")

	key, err := getOrCreateCacheKey(store)
	if err != nil {
		t.Fatalf("getOrCreateCacheKey() error = %v", err)
	}
	if err := SaveSignedCache(filename, map[string]string{"value": "original"}, key); err != nil {
		t.Fatalf("SaveSignedCache() error = %v", err)
	}

	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", filename, err)
	}
	var signed SignedCache
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	signed.HMAC = strings.Repeat("0", len(signed.HMAC))

	rewritten, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(filename, rewritten, 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filename, err)
	}

	var loaded map[string]string
	err = LoadSignedCache(filename, key, &loaded)
	if !errors.Is(err, ErrCacheTampered) {
		t.Fatalf("LoadSignedCache() error = %v, want ErrCacheTampered", err)
	}
}

func TestLoadSignedCacheRejectsMissingVersion(t *testing.T) {
	filename := t.TempDir() + "/missing-version.json"
	if err := os.WriteFile(filename, []byte(`{"data":"e30=","hmac":"abcd"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filename, err)
	}

	var loaded map[string]any
	err := LoadSignedCache(filename, []byte("01234567890123456789012345678901"), &loaded)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "missing version") {
		t.Fatalf("error = %q, want missing version", err.Error())
	}
}

func TestLoadSignedCacheRejectsInvalidBase64Data(t *testing.T) {
	filename := t.TempDir() + "/invalid-base64.json"
	if err := os.WriteFile(filename, []byte(`{"version":1,"data":"%%%","hmac":"abcd"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filename, err)
	}

	var loaded map[string]any
	err := LoadSignedCache(filename, []byte("01234567890123456789012345678901"), &loaded)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode cache data") {
		t.Fatalf("error = %q, want base64 decode error", err.Error())
	}
}

func TestLoadSignedCacheRejectsInvalidHMACFormat(t *testing.T) {
	filename := t.TempDir() + "/invalid-hmac.json"
	if err := os.WriteFile(filename, []byte(`{"version":1,"data":"e30=","hmac":"zzzz"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", filename, err)
	}

	var loaded map[string]any
	err := LoadSignedCache(filename, []byte("01234567890123456789012345678901"), &loaded)
	if !errors.Is(err, ErrCacheTampered) {
		t.Fatalf("LoadSignedCache() error = %v, want ErrCacheTampered", err)
	}
}

func TestVerifyHMACRejectsMalformedSignature(t *testing.T) {
	err := VerifyHMAC([]byte("payload"), "not-hex", []byte("01234567890123456789012345678901"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid HMAC format") {
		t.Fatalf("error = %q, want invalid HMAC format", err.Error())
	}
}
