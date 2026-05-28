// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/clientdata"
	"github.com/aplane-algo/aplane/internal/fsutil"
)

// ErrCacheTampered is returned when HMAC verification fails on a cache file,
// indicating the file has been modified outside of the application.
var ErrCacheTampered = errors.New("cache integrity check failed")

const (
	signedCacheEnvelopeVersion = 1
	cachePayloadSchemaVersion  = 1
)

type cachePayloadVersioner interface {
	cachePayloadSchemaVersion() int
	setCachePayloadSchemaVersion(version int)
}

func storePath(store *Store, filename string) string {
	if store == nil {
		return NewStore("").path(filename)
	}
	return store.path(filename)
}

// SignedCache represents cache data with HMAC signature.
type SignedCache struct {
	Version int    `json:"version"`
	Data    string `json:"data"`
	HMAC    string `json:"hmac"`
}

func cacheDir(store *Store) string {
	if store == nil {
		return NewStore("").dir()
	}
	return store.dir()
}

func getOrCreateCacheKey(store *Store) ([]byte, error) {
	keyFile := storePath(store, ".cache_key")

	key, err := readCacheKeyFile(keyFile)
	if err == nil {
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate cache key: %w", err)
	}

	if err := fsutil.MkdirAll(cacheDir(store)); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	created, err := createCacheKeyFileAtomically(keyFile, key)
	if err != nil {
		return nil, err
	}
	if created {
		infof("cache integrity protection initialized")
		return key, nil
	}
	return readCacheKeyFile(keyFile)
}

func readCacheKeyFile(keyFile string) ([]byte, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to read cache key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid cache key length: expected 32 bytes, got %d", len(key))
	}
	return key, nil
}

func createCacheKeyFileAtomically(keyFile string, key []byte) (bool, error) {
	dir := filepath.Dir(keyFile)
	tmp, err := os.CreateTemp(dir, filepath.Base(keyFile)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("failed to create cache key temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(key); err != nil {
		return false, fmt.Errorf("failed to write cache key temp file: %w", err)
	}
	if err := tmp.Chmod(fsutil.StoreFilePerm); err != nil {
		return false, fmt.Errorf("failed to set cache key permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		closed = true
		return false, fmt.Errorf("failed to close cache key temp file: %w", err)
	}
	closed = true

	if err := os.Link(tmpPath, keyFile); err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to publish cache key: %w", err)
	}
	return true, nil
}

func signCacheData(data []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC verifies that the HMAC signature matches the data.
func VerifyHMAC(data []byte, signatureHex string, key []byte) error {
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid HMAC format: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, signature) {
		return fmt.Errorf("HMAC verification failed - cache file has been tampered with")
	}
	return nil
}

// SaveSignedCache saves cache data with HMAC signature.
func SaveSignedCache(filePath string, data interface{}, key []byte) error {
	return saveSignedCache(filePath, data, key, nil)
}

func saveSignedCache(filePath string, data interface{}, key []byte, store *Store) error {
	ensureCachePayloadSchemaVersion(data)

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %w", err)
	}

	signed := SignedCache{
		Version: signedCacheEnvelopeVersion,
		Data:    base64.StdEncoding.EncodeToString(dataBytes),
		HMAC:    signCacheData(dataBytes, key),
	}

	output, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signed cache: %w", err)
	}

	if err := fsutil.MkdirAll(cacheDir(store)); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	return fsutil.WriteFile(filePath, output)
}

func saveSignedCacheWithoutClientLock(store *Store, filePath string, data interface{}) error {
	key, err := getOrCreateCacheKey(store)
	if err != nil {
		return fmt.Errorf("failed to get cache key: %w", err)
	}
	return saveSignedCache(filePath, data, key, store)
}

func ensureCacheDir(store *Store) error {
	if err := fsutil.MkdirAll(cacheDir(store)); err != nil {
		return fmt.Errorf("failed to create cache directory %s: %w", cacheDir(store), err)
	}
	return nil
}

func warnCacheLoadError(cacheName string, err error) {
	if errors.Is(err, ErrCacheTampered) {
		warnf("SECURITY: %s may have been tampered with — starting with empty cache: %v", cacheName, err)
	} else {
		warnf("failed to load %s: %v", cacheName, err)
	}
}

func loadSignedCacheWithKey(store *Store, filePath string, target interface{}) error {
	if err := ensureCacheDir(store); err != nil {
		return err
	}

	key, err := getOrCreateCacheKey(store)
	if err != nil {
		return fmt.Errorf("failed to get cache key: %w", err)
	}
	return LoadSignedCache(filePath, key, target)
}

func saveSignedCacheWithKey(store *Store, filePath string, data interface{}) error {
	save := func() error {
		return saveSignedCacheWithoutClientLock(store, filePath, data)
	}
	if store != nil && store.clientDataDir() != "" {
		return clientdata.WithExclusiveLock(store.clientDataDir(), save)
	}
	return save()
}

// LoadSignedCache loads and verifies cache data.
func LoadSignedCache(filePath string, key []byte, target interface{}) error {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	var signed SignedCache
	if err := json.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("failed to parse cache file: %w", err)
	}
	if signed.Version == 0 {
		return fmt.Errorf("invalid cache file: missing version")
	}
	if signed.Version != signedCacheEnvelopeVersion {
		return fmt.Errorf("unsupported cache envelope version %d (supported %d)", signed.Version, signedCacheEnvelopeVersion)
	}

	dataBytes, err := base64.StdEncoding.DecodeString(signed.Data)
	if err != nil {
		return fmt.Errorf("failed to decode cache data: %w", err)
	}

	if err := VerifyHMAC(dataBytes, signed.HMAC, key); err != nil {
		return ErrCacheTampered
	}

	if err := validateCachePayloadSchemaVersion(dataBytes, target); err != nil {
		return err
	}
	if err := json.Unmarshal(dataBytes, target); err != nil {
		return fmt.Errorf("failed to unmarshal cache data: %w", err)
	}
	ensureCachePayloadSchemaVersion(target)
	return nil
}

func ensureCachePayloadSchemaVersion(data interface{}) {
	payload, ok := data.(cachePayloadVersioner)
	if !ok || payload.cachePayloadSchemaVersion() != 0 {
		return
	}
	payload.setCachePayloadSchemaVersion(cachePayloadSchemaVersion)
}

func validateCachePayloadSchemaVersion(dataBytes []byte, target interface{}) error {
	if _, ok := target.(cachePayloadVersioner); !ok {
		return nil
	}

	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(dataBytes, &header); err != nil {
		return fmt.Errorf("failed to inspect cache payload schema_version: %w", err)
	}
	if header.SchemaVersion == 0 {
		return nil
	}
	if header.SchemaVersion != cachePayloadSchemaVersion {
		return fmt.Errorf("unsupported cache payload schema_version %d (supported %d)", header.SchemaVersion, cachePayloadSchemaVersion)
	}
	return nil
}
