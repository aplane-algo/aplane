// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keystore

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/signingargs"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
)

// FileKeyStore implements KeyStore using encrypted files on disk
type FileKeyStore struct {
	active *storepaths.GenPaths

	// Cache of address -> KeyScanInfo, installed from a scan with the
	// binding (Install).
	cache     map[string]keys.KeyScanInfo
	cacheLock sync.RWMutex

	// The store's keyring, opened once at unlock and zeroed on lock.
	keyring *crypto.Keyring
	// keyringUsers counts the WithKeyring callbacks running with keyring.
	// They hold no lock, so whoever detaches the keyring waits for them
	// before zeroing it. Both fields change together, under cacheLock.
	keyringUsers *sync.WaitGroup
}

// SigningSummary is the non-sensitive key-file signing metadata cached at scan time.
type SigningSummary struct {
	Category             string
	BaseKeyType          string
	Parameters           map[string]string
	SigningArgs          []lsigprovider.RuntimeArgDef
	BoundedAuthorization *boundedmeta.Metadata
	TemplateFingerprint  string
	LogicSigResources    *lsigresource.Profile
	// ValidRekeyTarget is the value the aplane key recorded at creation.
	ValidRekeyTarget bool
}

// NewFileKeyStore creates a file store holding no keyring, binding or keys
// until a publish installs them (Install).
func NewFileKeyStore() *FileKeyStore {
	return &FileKeyStore{cache: make(map[string]keys.KeyScanInfo)}
}

// Contents is what the store holds besides its keyring: the generation it
// is bound to and the key cache scanned from it. It owns no key material.
type Contents struct {
	// Selection is the generation the store root selected, authenticated;
	// nil when the root did not authenticate.
	Selection *storepaths.GenPaths
	Keys      map[string]keys.KeyScanInfo
	Warnings  []keys.KeyScanWarning
}

// ScanGeneration scans selected, a generation the caller authenticated and
// validated, with kr, and installs nothing. It returns the selection on a
// failure too.
func ScanGeneration(selected storepaths.GenPaths, kr *crypto.Keyring) (Contents, error) {
	contents := Contents{Selection: &selected}
	report, err := keys.ScanKeysDirectory(selected, kr, nil)
	if err != nil {
		return contents, fmt.Errorf("failed to scan keys directory: %w", err)
	}
	contents.Keys = report.Keys
	contents.Warnings = append([]keys.KeyScanWarning(nil), report.Warnings...)
	return contents, nil
}

// Install replaces the store's keyring with kr, which may be nil to close
// it, and its contents, together under the cache lock: a reader sees all of
// the old or all of the new. It returns the keyring it replaced, which the
// caller zeroes with ZeroWhenUnused once it has released its own locks; it
// is not zeroed while a WithKeyring callback still uses it.
func (f *FileKeyStore) Install(kr *crypto.Keyring, contents Contents) DetachedKeyring {
	f.cacheLock.Lock()
	defer f.cacheLock.Unlock()
	return f.installLocked(kr, contents)
}

func (f *FileKeyStore) installLocked(kr *crypto.Keyring, contents Contents) DetachedKeyring {
	previous := f.replaceKeyringLocked(kr)
	f.active = contents.Selection
	f.cache = contents.Keys
	if f.cache == nil {
		f.cache = make(map[string]keys.KeyScanInfo)
	}
	return previous
}

// WithKeyring executes fn with the store's keyring, which is not zeroed
// until fn returns. This is the API callers should use: it hands out
// operations, not key material.
//
// fn runs without the cache lock. It is the callers' code, and it reads the
// store again (an admin service's key paths are the store's active paths);
// a second read lock taken while a lock's ClearKeys waits for the first
// would deadlock the store. The keyring is held instead by a count that
// ClearKeys and Install wait for. fn may read the store and call WithKeyring;
// it must not, on its own goroutine, call ClearKeys, Install, or anything
// that does (a lock, a publish that replaces the keyring): they wait for fn.
func (f *FileKeyStore) WithKeyring(fn func(kr *crypto.Keyring) error) error {
	f.cacheLock.RLock()
	kr, users := f.keyring, f.keyringUsers
	if kr == nil {
		f.cacheLock.RUnlock()
		return fmt.Errorf("keystore not unlocked (keyring not available): %w", ErrStoreLocked)
	}
	users.Add(1)
	f.cacheLock.RUnlock()
	defer users.Done()
	return fn(kr)
}

// DetachedKeyring is a keyring taken off the store, with the WithKeyring
// callbacks still using it.
type DetachedKeyring struct {
	keyring *crypto.Keyring
	users   *sync.WaitGroup
}

// replaceKeyringLocked installs kr, which may be nil, and returns the keyring
// it replaces. The caller holds cacheLock for writing and, once it has
// released it, zeroes what was returned with ZeroWhenUnused. Readers that
// use the keyring under the lock (Get) are done with it by then; the lock
// excluded them.
func (f *FileKeyStore) replaceKeyringLocked(kr *crypto.Keyring) DetachedKeyring {
	if kr != nil && kr == f.keyring {
		// Installing the keyring already installed changes nothing, and
		// returning it would zero the live keyring.
		return DetachedKeyring{}
	}
	previous := DetachedKeyring{keyring: f.keyring, users: f.keyringUsers}
	f.keyring, f.keyringUsers = kr, nil
	if kr != nil {
		f.keyringUsers = &sync.WaitGroup{}
	}
	return previous
}

// ZeroWhenUnused waits for the callbacks still using the keyring, then
// zeroes it. It is called without the cache lock, which they may need.
func (d DetachedKeyring) ZeroWhenUnused() {
	if d.keyring == nil {
		return
	}
	d.users.Wait()
	d.keyring.Zero()
}

// ClearKeys securely zeros every term key and drops the keyring, the
// binding and the key cache. Called when the signer locks so no key material
// remains resident. It returns once the keyring is zeroed, after any
// WithKeyring callback still using it returns; meanwhile the store reads as
// locked.
func (f *FileKeyStore) ClearKeys() {
	f.Install(nil, Contents{}).ZeroWhenUnused()
}

// ActivePaths returns the generation authenticated by the most recent atomic
// root unlock or reload. The returned value is a copy and carries no key
// material.
func (f *FileKeyStore) ActivePaths() (storepaths.GenPaths, error) {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	if f.keyring == nil {
		return storepaths.GenPaths{}, fmt.Errorf("store is not unlocked: %w", ErrStoreLocked)
	}
	if f.active == nil {
		return storepaths.GenPaths{}, fmt.Errorf("atomic store root is not unlocked: %w", ErrStoreLocked)
	}
	return *f.active, nil
}

// Get retrieves key material for signing.
// The keystore must hold an installed keyring and key cache (Install).
// Holds the cache read lock through decryption to prevent ClearKeys() from
// zeroing the term keys mid-operation.
func (f *FileKeyStore) Get(ctx context.Context, address string) (*signing.KeyMaterial, error) {
	f.cacheLock.RLock()
	info, exists := f.cache[address]
	if !exists {
		f.cacheLock.RUnlock()
		return nil, ErrKeyNotFound
	}
	if f.keyring == nil {
		f.cacheLock.RUnlock()
		return nil, fmt.Errorf("keystore not unlocked: %w", ErrStoreLocked)
	}
	// Decrypt under the read lock, straight from the keyring: no term key
	// copy is made, so none can outlive the lock or survive ClearKeys.
	decryptedData, err := keys.ReadDecryptedKeyJSONWithKeyring(info.KeyFile, f.keyring)
	f.cacheLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	defer crypto.ZeroBytes(decryptedData)

	payload, err := keys.ParseStoredPayload(decryptedData)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()
	selector, err := payload.Selector()
	if err != nil {
		return nil, err
	}
	if selector != address {
		return nil, fmt.Errorf("key payload selector %s does not match requested selector %s", selector, address)
	}
	if payload.KeyType != info.KeyType || payload.Category != info.Category {
		return nil, fmt.Errorf("key payload identity changed after scan")
	}

	// Use key type from cache (already determined during scan)
	keyType := info.KeyType
	signingMeta := payload.SigningMetadata()

	// Generic lsig types (timelock, etc.) don't have signing providers
	// They only need bytecode attachment, no cryptographic signing
	if keys.IsGenericKey(signingMeta.Category) {
		return loadGenericLsigKeys(payload, keyType, signingMeta), nil
	}

	if keys.IsWitnessKey(signingMeta.Category) {
		return loadWitnessKeyMaterial(payload, keyType, signingMeta)
	}

	// Rotating accounts sign only through stage operations, never through an
	// ordinary signing provider.
	if signingMeta.Category == keys.CategoryRotatingLsig {
		return &signing.KeyMaterial{
			Type:     keyType,
			Category: signingMeta.Category,
			Value: &signing.RotatingKeyMaterial{
				Seed:        bytes.Clone(payload.PrivateKey),
				GenesisHash: bytes.Clone(payload.GenesisHash),
			},
		}, nil
	}

	// Get provider and load keys (for ed25519, falcon, etc.)
	provider := signing.GetProviderForKey(keyType, signingMeta.BaseKeyType)
	if provider == nil {
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	providerKey := signing.ProviderKey{
		Type:        keyType,
		BaseKeyType: signingMeta.BaseKeyType,
		PrivateKey:  payload.PrivateKey,
	}
	km, err := provider.LoadKeyMaterial(providerKey)
	if err != nil {
		return nil, err
	}
	// The keystore owns the KeyMaterial envelope: storage metadata is stamped
	// unconditionally from the validated payload, so providers only supply
	// Type and the cryptographic Value.
	km.Category = signingMeta.Category
	km.BaseKeyType = signingMeta.BaseKeyType
	km.Bytecode = bytes.Clone(payload.LogicSigBytecode)
	km.PublicKey = bytes.Clone(payload.PublicKey)
	km.Parameters = maps.Clone(signingMeta.Parameters)
	km.SigningArgs = signingargs.ToRuntimeDefs(signingMeta.SigningArgs)
	km.BoundedAuthorization = boundedmeta.Clone(signingMeta.BoundedAuthorization)
	return km, nil
}

// loadGenericLsigKeys loads key material for generic lsig types (timelock, etc.)
// These don't have cryptographic keys - just bytecode that gets attached to
// transactions - so Value stays nil.
func loadGenericLsigKeys(payload *keys.Payload, keyType string, signingMeta keys.SigningMetadata) *signing.KeyMaterial {
	return &signing.KeyMaterial{
		Type:                 keyType,
		Category:             signingMeta.Category,
		Bytecode:             bytes.Clone(payload.LogicSigBytecode),
		Parameters:           maps.Clone(signingMeta.Parameters),
		SigningArgs:          signingargs.ToRuntimeDefs(signingMeta.SigningArgs),
		BoundedAuthorization: boundedmeta.Clone(signingMeta.BoundedAuthorization),
	}
}

// loadWitnessKeyMaterial projects an already-validated witness payload into
// KeyMaterial. ParsePayload enforced the witness key type, key sizes, and
// the public/private pair before Get reaches this point, so only cloning and
// selector derivation remain.
func loadWitnessKeyMaterial(payload *keys.Payload, keyType string, signingMeta keys.SigningMetadata) (*signing.KeyMaterial, error) {
	publicKey := bytes.Clone(payload.PublicKey)
	privateKey := bytes.Clone(payload.PrivateKey)

	componentKey, err := witness.ID(keyType, publicKey)
	if err != nil {
		crypto.ZeroBytes(publicKey)
		crypto.ZeroBytes(privateKey)
		return nil, err
	}

	return &signing.KeyMaterial{
		Type:       keyType,
		Category:   signingMeta.Category,
		PublicKey:  append([]byte(nil), publicKey...),
		Parameters: maps.Clone(signingMeta.Parameters),
		Value: &signing.WitnessKeyMaterial{
			WitnessKeyID: componentKey,
			PublicKey:    publicKey,
			PrivateKey:   privateKey,
		},
	}, nil
}

// KeyFiles is the address -> key file path map of the scanned keys.
func (c Contents) KeyFiles() map[string]string {
	result := make(map[string]string, len(c.Keys))
	for k, v := range c.Keys {
		result[k] = v.KeyFile
	}
	return result
}

// GetKeyTypes returns a copy of the address -> keyType cache
func (f *FileKeyStore) GetKeyTypes() map[string]string {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	return Contents{Keys: f.cache}.KeyTypes()
}

// KeyTypes is the address -> key type map of the scanned keys.
func (c Contents) KeyTypes() map[string]string {
	result := make(map[string]string, len(c.Keys))
	for k, v := range c.Keys {
		result[k] = v.KeyType
	}
	return result
}

// GetSigningSummary returns one scan-time snapshot of address -> non-sensitive
// signing metadata. The returned map, its Parameters maps, and its
// BoundedAuthorization records are freshly built per call and owned by the
// caller — no further defensive cloning is required. Only tests read it, and
// the test seam productruntime.Runtime.PublishSnapshot: production reads the
// runtime's published snapshot.
func (f *FileKeyStore) GetSigningSummary() map[string]SigningSummary {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	return Contents{Keys: f.cache}.SigningSummaries()
}

// SigningSummaries is the address -> non-sensitive signing metadata map of
// the scanned keys, freshly built and owned by the caller.
func (c Contents) SigningSummaries() map[string]SigningSummary {
	result := make(map[string]SigningSummary, len(c.Keys))
	for k, v := range c.Keys {
		summary := SigningSummary{
			Category:             v.Category,
			BaseKeyType:          v.BaseKeyType,
			Parameters:           maps.Clone(v.Parameters),
			BoundedAuthorization: boundedmeta.Clone(v.BoundedAuthorization),
			TemplateFingerprint:  v.TemplateFingerprint,
			ValidRekeyTarget:     v.ValidRekeyTarget,
		}
		if v.LogicSigResources != nil {
			cloned := v.LogicSigResources.Clone()
			summary.LogicSigResources = &cloned
		}
		if len(v.SigningArgs) > 0 {
			summary.SigningArgs = signingargs.ToRuntimeDefs(v.SigningArgs)
		}
		result[k] = summary
	}
	return result
}

// GetPublicKeyHexMap returns a copy of the address -> publicKeyHex cache.
// Returns empty string for generic LSig keys.
func (f *FileKeyStore) GetPublicKeyHexMap() map[string]string {
	f.cacheLock.RLock()
	defer f.cacheLock.RUnlock()
	return Contents{Keys: f.cache}.PublicKeyHexes()
}

// PublicKeyHexes is the address -> public key hex map of the scanned keys;
// empty for generic LogicSig keys.
func (c Contents) PublicKeyHexes() map[string]string {
	result := make(map[string]string, len(c.Keys))
	for k, v := range c.Keys {
		result[k] = v.PublicKeyHex
	}
	return result
}

// Compile-time interface check
var _ sessionKeyStore = (*FileKeyStore)(nil)
