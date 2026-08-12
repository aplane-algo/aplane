// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signingargs"
)

// ASAInfo contains information about an Algorand Standard Asset
type ASAInfo struct {
	Decimals uint64 `json:"decimals"`
	Name     string `json:"name"`
	UnitName string `json:"unit_name"`
}

// ASACache stores cached ASA information per network
type ASACache struct {
	SchemaVersion int                `json:"schema_version,omitempty"`
	Assets        map[uint64]ASAInfo `json:"assets"`
	store         *Store
}

// AliasCache stores address aliases
type AliasCache struct {
	SchemaVersion int               `json:"schema_version,omitempty"`
	Aliases       map[string]string `json:"aliases"`
	store         *Store
}

// SignerCache stores addresses that Signer has private keys for (can sign remotely)
// Maps: address -> key type ("aplane.falcon1024.v1" or "ed25519")
type SignerCache struct {
	SchemaVersion           int                             `json:"schema_version,omitempty"`
	Keys                    map[string]string               `json:"keys"`          // address -> key type
	GenericLsigs            map[string]bool                 `json:"generic_lsigs"` // address -> true if generic lsig (no signature needed)
	LogicSigResources       map[string]lsigresource.Profile `json:"logic_sig_resources,omitempty"`
	SigningArgs             map[string][]SigningArgInfo     `json:"signing_args"`                         // address -> key-file signing arg schema for LogicSigs
	SigningFlows            map[string]string               `json:"signing_flows,omitempty"`              // address -> signing choreography label (e.g. "sentry1"); empty = plain /sign
	SentryComponentKeyTypes map[string]string               `json:"sentry_component_key_types,omitempty"` // address -> sentry component key type for signing_flow "sentry1"
	SentryPublicKeys        map[string]string               `json:"sentry_public_keys,omitempty"`         // address -> embedded sentry public key hex
	BoundedMaxFees          map[string]uint64               `json:"bounded_max_fees,omitempty"`           // address -> bounded authorization max_fee
	Locked                  bool                            `json:"-"`                                    // True if signer reported 403 (locked) on last /keys check
	store                   *Store
}

// AuthAddressCache stores cached auth addresses to avoid repeated blockchain queries
// Maps: account address -> auth address (empty string if not rekeyed)
//
// Like the other caches in this package, AuthAddressCache is not internally
// synchronized: instances are confined to their host's single command
// goroutine (see clientstate.State), and cross-process consistency comes from
// the signed cache files plus the clientdata exclusive lock. It previously
// embedded a mutex, but the cache is copied and wholesale-reassigned on every
// reload, so a per-instance lock never provided real protection.
type AuthAddressCache struct {
	SchemaVersion int               `json:"schema_version,omitempty"`
	AuthAddresses map[string]string `json:"auth_addresses"` // address -> auth address (or "" if not rekeyed)
	store         *Store
}

func (c *ASACache) cachePayloadSchemaVersion() int {
	return c.SchemaVersion
}

func (c *ASACache) setCachePayloadSchemaVersion(version int) {
	c.SchemaVersion = version
}

func (c *ASACache) supportedCachePayloadSchemaVersion() int {
	return cachePayloadSchemaVersion
}

func (c *AliasCache) cachePayloadSchemaVersion() int {
	return c.SchemaVersion
}

func (c *AliasCache) setCachePayloadSchemaVersion(version int) {
	c.SchemaVersion = version
}

func (c *AliasCache) supportedCachePayloadSchemaVersion() int {
	return cachePayloadSchemaVersion
}

func (c *SignerCache) cachePayloadSchemaVersion() int {
	return c.SchemaVersion
}

func (c *SignerCache) setCachePayloadSchemaVersion(version int) {
	c.SchemaVersion = version
}

func (c *SignerCache) supportedCachePayloadSchemaVersion() int {
	return signerCachePayloadSchemaVersion
}

func (c *AuthAddressCache) cachePayloadSchemaVersion() int {
	return c.SchemaVersion
}

func (c *AuthAddressCache) setCachePayloadSchemaVersion(version int) {
	c.SchemaVersion = version
}

func (c *AuthAddressCache) supportedCachePayloadSchemaVersion() int {
	return cachePayloadSchemaVersion
}

func (c *ASACache) bindStore(store *Store) {
	c.store = store
}

func (c *AliasCache) bindStore(store *Store) {
	c.store = store
}

func (c *AuthAddressCache) bindStore(store *Store) {
	c.store = store
}

func (c *SignerCache) bindStore(store *Store) {
	c.store = store
}

// BindStore associates the signer cache with a cache store for persistence.
func (c *SignerCache) BindStore(store *Store) {
	c.bindStore(store)
}

func (c *SetCache) bindStore(store *Store) {
	c.store = store
}

// SigningArgInfo describes a key-file signing argument for LogicSig keys.
type SigningArgInfo = signingargs.Info
