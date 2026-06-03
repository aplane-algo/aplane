// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"sync"

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
	SchemaVersion      int                         `json:"schema_version,omitempty"`
	Keys               map[string]string           `json:"keys"`                           // address -> key type
	GenericLsigs       map[string]bool             `json:"generic_lsigs"`                  // address -> true if generic lsig (no signature needed)
	LsigSizes          map[string]int              `json:"lsig_sizes"`                     // address -> total LSig size (bytecode + crypto sig) for budget calculation
	SigningArgs        map[string][]SigningArgInfo `json:"signing_args"`                   // address -> key-file signing arg schema for LogicSigs
	AttestorPublicKeys map[string]string           `json:"attestor_public_keys,omitempty"` // address -> embedded attestor Ed25519 public key hex
	Locked             bool                        `json:"-"`                              // True if signer reported 403 (locked) on last /keys check
	store              *Store
}

// AuthAddressCache stores cached auth addresses to avoid repeated blockchain queries
// Maps: account address -> auth address (empty string if not rekeyed)
type AuthAddressCache struct {
	SchemaVersion int               `json:"schema_version,omitempty"`
	AuthAddresses map[string]string `json:"auth_addresses"` // address -> auth address (or "" if not rekeyed)
	store         *Store
	mu            *sync.RWMutex `json:"-"`
}

func (c *ASACache) cachePayloadSchemaVersion() int {
	return c.SchemaVersion
}

func (c *ASACache) setCachePayloadSchemaVersion(version int) {
	c.SchemaVersion = version
}

func (c *AliasCache) cachePayloadSchemaVersion() int {
	return c.SchemaVersion
}

func (c *AliasCache) setCachePayloadSchemaVersion(version int) {
	c.SchemaVersion = version
}

func (c *SignerCache) cachePayloadSchemaVersion() int {
	return c.SchemaVersion
}

func (c *SignerCache) setCachePayloadSchemaVersion(version int) {
	c.SchemaVersion = version
}

func (c *AuthAddressCache) cachePayloadSchemaVersion() int {
	return c.SchemaVersion
}

func (c *AuthAddressCache) setCachePayloadSchemaVersion(version int) {
	c.SchemaVersion = version
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
