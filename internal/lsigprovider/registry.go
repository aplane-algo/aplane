// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/xregistry"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// normalize lowercases a key type for consistent lookups.
func normalize(s string) string {
	return strings.ToLower(s)
}

var (
	providers = xregistry.NewStringRegistry[LSigProvider]()
	// storedClient is the algod client applied to late-registered providers.
	// registerMu guards it.
	storedClient *algod.Client
	registerMu   sync.Mutex
)

// Register adds an LSigProvider to the unified process-global registry.
// Key type names are compatibility names shared by every identity in the
// process; identity-private provider namespaces are not supported.
// Key types are normalized to lowercase.
// Panics if a provider for the same key type is already registered.
// If an algod client was previously configured, it is automatically applied
// to providers that implement AlgodConfigurable.
func Register(p LSigProvider) {
	registerMu.Lock()
	defer registerMu.Unlock()

	keyType := validateProviderContract(p)
	if !providers.Set(keyType, p) {
		panic("duplicate LSig provider registration for key type: " + keyType)
	}

	applyStoredClientIfNeeded(p)
}

// RegisterIfAbsent adds an LSigProvider to the unified registry unless the
// key type is already present. It returns true when the provider was newly
// registered and false when the key type already existed.
//
// Compiled providers that may register more than once in a process use it;
// a reload registers its templates as a batch (ProcessRegistry). Callers that
// want duplicate registration to remain a hard failure use Register.
func RegisterIfAbsent(p LSigProvider) bool {
	registerMu.Lock()
	defer registerMu.Unlock()

	keyType := validateProviderContract(p)
	if !providers.Set(keyType, p) {
		return false
	}

	applyStoredClientIfNeeded(p)
	return true
}

// Unregister removes a provider from the registry, reporting whether it was
// present. It exists for the template removal and failed-install rollback
// paths, which delete the template's files and records and must also release
// the process-global key-type name so a corrected template can be installed
// without restarting the daemon. Compiled family providers must never be
// unregistered; callers pass key types read from installed-template records.
func Unregister(keyType string) bool {
	registerMu.Lock()
	defer registerMu.Unlock()
	return providers.Delete(normalize(strings.TrimSpace(keyType)))
}

// Get retrieves an LSigProvider by its key type.
// Input is normalized to lowercase.
// Returns nil if not found.
func Get(keyType string) LSigProvider {
	p, _ := providers.Get(normalize(keyType))
	return p
}

// GetOrError retrieves an LSigProvider by its key type.
// Input is normalized to lowercase.
// Returns an error if not found.
func GetOrError(keyType string) (LSigProvider, error) {
	if p, ok := providers.Get(normalize(keyType)); ok {
		return p, nil
	}
	return nil, fmt.Errorf("no LSig provider found for: %s", keyType)
}

// GetAll returns all registered LSigProviders, sorted by KeyType.
func GetAll() []LSigProvider {
	return providers.Values()
}

// Has checks if a key type is registered.
// Input is normalized to lowercase.
func Has(keyType string) bool {
	return providers.Has(normalize(keyType))
}

// CompatibilityFingerprintOf returns the semantic compatibility fingerprint for
// a provider when it implements CompatibilityFingerprinter.
func CompatibilityFingerprintOf(p LSigProvider) (string, bool) {
	fingerprinter, ok := p.(CompatibilityFingerprinter)
	if !ok {
		return "", false
	}
	return fingerprinter.CompatibilityFingerprint(), true
}

// RoutingFamily is the RESOLVE axis of key-type resolution (see
// docs/ARCH_KEYTYPES.md): it maps a key type to the registry key used to find
// its implementation. Route by this declared family, NOT by BaseKeyType — a
// cosigned account's BaseKeyType is its component-signing primitive, not its
// routing authority, so BaseKeyType cannot express the delegate-vs-self
// distinction that this does.
//
// RoutingFamily returns the provider-declared ROUTING family for a key type —
// the family under which the key type's keygen/signing/mnemonic/metadata ops are
// registered, which is how the family-keyed registries are indexed. For a
// self-handling DSA this is its own family; for a composed template that
// delegates to a base it is the base's family (e.g.
// "example.falcon1024-allowlist.v1" -> "aplane.falcon1024").
//
// It is NOT the key type's own display label. The routing family of a composed
// template is intentionally its base's family, not the template's own — so do
// not use this where you want the key type's own "publisher.family".
//
// Input is normalized to lowercase. If the key type is not registered, the
// normalized input is returned unchanged.
func RoutingFamily(keyType string) string {
	normalized := normalize(keyType)
	if p, ok := providers.Get(normalized); ok {
		return strings.ToLower(p.RoutingFamily())
	}
	return normalized
}

// AlgodConfigurable is an optional interface for LSigProvider implementations
// that require an algod client for TEAL compilation (e.g., ComposedDSA).
type AlgodConfigurable interface {
	SetAlgodClient(client *algod.Client)
}

// ConfigureAlgodClient sets the algod client on all registered providers that
// implement AlgodConfigurable. This enables runtime TEAL compilation for
// composed providers during key import and derivation.
//
// The client is stored so that providers registered later (e.g., from keystore
// templates loaded after unlock) are automatically configured.
//
// Should be called during server startup after initial providers are registered.
func ConfigureAlgodClient(client *algod.Client) {
	registerMu.Lock()
	defer registerMu.Unlock()

	storedClient = client
	for _, p := range GetAll() {
		if configurable, ok := p.(AlgodConfigurable); ok {
			configurable.SetAlgodClient(client)
		}
	}
}

// validateProviderContract panics when p breaks the provider contract, and
// returns its normalized key type. Compiled providers register at process
// start, where a broken one is a build defect.
func validateProviderContract(p LSigProvider) string {
	keyType, err := CheckContract(p)
	if err != nil {
		panic(err.Error())
	}
	return keyType
}

// CheckContract reports whether p keeps the provider contract every
// registered provider keeps, and returns its normalized key type. A
// template's preparation runs it, so a template whose provider breaks it is
// refused there instead of panicking at registration.
func CheckContract(p LSigProvider) (string, error) {
	rawKeyType := strings.TrimSpace(p.KeyType())
	if rawKeyType == "" {
		return "", fmt.Errorf("LSig provider has empty key type")
	}
	if strings.ContainsAny(rawKeyType, " \t\r\n") {
		return "", fmt.Errorf("LSig provider key type contains whitespace: %s", rawKeyType)
	}

	family := strings.TrimSpace(p.RoutingFamily())
	if family == "" {
		return "", fmt.Errorf("LSig provider has empty family for key type: %s", rawKeyType)
	}
	if strings.ContainsAny(family, " \t\r\n") {
		return "", fmt.Errorf("LSig provider family contains whitespace: %s", family)
	}

	if p.Version() <= 0 {
		return "", fmt.Errorf("LSig provider has invalid version %d for key type: %s", p.Version(), rawKeyType)
	}

	switch category := p.Category(); category {
	case CategoryGenericLsig, CategoryDSALsig:
		// OK
	default:
		return "", fmt.Errorf("LSig provider has invalid category %q for key type: %s", category, rawKeyType)
	}

	return normalize(rawKeyType), nil
}

// ProcessRegistry is the process-wide provider registry, as the handle a
// runtime is given: a reload registers its templates and reads the providers
// registered before it through that handle, not through the package
// functions. A registry per identity would replace it.
type ProcessRegistry struct{}

// Get returns the registered provider for keyType, or nil.
func (ProcessRegistry) Get(keyType string) LSigProvider { return Get(keyType) }

// Unregister removes keyType's provider and reports whether it was
// registered: a removed or disabled template's, so its key type name is free
// again and no key of the type signs.
func (ProcessRegistry) Unregister(keyType string) bool { return Unregister(keyType) }

// RegisterBatchIfAbsent registers each provider whose key type is not yet
// present, all under one hold of the registration lock, and reports for each
// whether it was newly registered. A batch with a provider that breaks the
// contract registers nothing. A template's preparation already checked each
// contract (CheckContract); the batch checks again, a deliberately layered
// guard, since what it registers is process-wide.
func (ProcessRegistry) RegisterBatchIfAbsent(batch []LSigProvider) ([]bool, error) {
	registerMu.Lock()
	defer registerMu.Unlock()
	keyTypes := make([]string, len(batch))
	for i, p := range batch {
		keyType, err := CheckContract(p)
		if err != nil {
			return nil, err
		}
		keyTypes[i] = keyType
	}
	registered := make([]bool, len(batch))
	for i, p := range batch {
		if providers.Set(keyTypes[i], p) {
			registered[i] = true
			applyStoredClientIfNeeded(p)
		}
	}
	return registered, nil
}

// applyStoredClientIfNeeded runs with registerMu held.
func applyStoredClientIfNeeded(p LSigProvider) {
	if storedClient == nil {
		return
	}
	if configurable, ok := p.(AlgodConfigurable); ok {
		configurable.SetAlgodClient(storedClient)
	}
}
