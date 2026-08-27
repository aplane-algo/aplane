// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

func TestReloadKeysKeepsOriginalGenericTemplateDefinition(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("phase0-reload-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	initialDisplayName := "Phase0 Initial Template"
	updatedDisplayName := "Phase0 Updated Template"

	if genericlsig.Get(keyType) != nil {
		t.Fatalf("test key type %q already registered; family generator must be unique", keyType)
	}

	before := fetchKeyTypesForTest(t, server)
	if _, ok := findKeyTypeInfo(before, keyType); ok {
		t.Fatalf("key type %q should not exist before template save/reload", keyType)
	}

	saveGenericTemplateForTest(t, server, keyType, renderGenericTemplateYAML(family, 1, initialDisplayName, "initial description"))

	if err := reloadKeysWithTemplatesForTest(server); err != nil {
		t.Fatalf("reloadKeysForTest(initial) error = %v", err)
	}

	afterFirstReload := fetchKeyTypesForTest(t, server)
	initialInfo, ok := findKeyTypeInfo(afterFirstReload, keyType)
	if !ok {
		t.Fatalf("key type %q not visible after reload", keyType)
	}
	if initialInfo.DisplayName != initialDisplayName {
		t.Fatalf("DisplayName after first reload = %q, want %q", initialInfo.DisplayName, initialDisplayName)
	}

	saveGenericTemplateForTest(t, server, keyType, renderGenericTemplateYAML(family, 1, updatedDisplayName, "updated description"))

	if err := reloadKeysWithTemplatesForTest(server); err != nil {
		t.Fatalf("reloadKeysForTest(update) error = %v", err)
	}

	afterSecondReload := fetchKeyTypesForTest(t, server)
	updatedInfo, ok := findKeyTypeInfo(afterSecondReload, keyType)
	if !ok {
		t.Fatalf("key type %q missing after second reload", keyType)
	}

	if updatedInfo.DisplayName != initialDisplayName {
		t.Fatalf("DisplayName after second reload = %q, want original %q", updatedInfo.DisplayName, initialDisplayName)
	}
}

func TestReloadKeysPreservesAlreadyRegisteredGenericDefinition(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("phase0-existing-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	initialDisplayName := "Phase0 Registered Template"
	conflictingDisplayName := "Phase0 Conflicting Keystore Template"

	registeredYAML := renderGenericTemplateYAML(family, 1, initialDisplayName, "registered definition")
	registerGenericTemplateProviderForTest(t, registeredYAML)
	saveGenericTemplateForTest(t, server, keyType, registeredYAML)

	before := fetchKeyTypesForTest(t, server)
	registeredInfo, ok := findKeyTypeInfo(before, keyType)
	if !ok {
		t.Fatalf("registered key type %q not visible before attempted collision", keyType)
	}
	if registeredInfo.DisplayName == conflictingDisplayName {
		t.Fatalf("precondition failed: embedded display name already %q", conflictingDisplayName)
	}

	saveGenericTemplateForTest(t, server, keyType, renderGenericTemplateYAML(family, 1, conflictingDisplayName, "attempt conflicting registered-template mutation"))

	if err := reloadKeysWithTemplatesForTest(server); err != nil {
		t.Fatalf("reloadKeysWithTemplatesForTest() error = %v", err)
	}

	after := fetchKeyTypesForTest(t, server)
	info, ok := findKeyTypeInfo(after, keyType)
	if !ok {
		t.Fatalf("key type %q missing after reload", keyType)
	}
	if info.DisplayName != registeredInfo.DisplayName {
		t.Fatalf("DisplayName after reload = %q, want registered %q", info.DisplayName, registeredInfo.DisplayName)
	}
}

func TestWatcherReloadWaitsForAdminIdentityMutation(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}

	var reloadFn func() error
	ir.EnsureKeyWatcher(func(_ []string, _ context.Context, fn func() error) error {
		reloadFn = fn
		return nil
	})
	if reloadFn == nil {
		t.Fatal("watcher reload function was not installed")
	}

	enteredMutation := make(chan struct{})
	releaseMutation := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- server.withStoreMutation(func() error {
			close(enteredMutation)
			<-releaseMutation
			return nil
		})
	}()
	<-enteredMutation

	reloadDone := make(chan error, 1)
	go func() {
		reloadDone <- reloadFn()
	}()

	select {
	case err := <-reloadDone:
		t.Fatalf("watcher reload completed while admin mutation lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseMutation)
	if err := <-mutationDone; err != nil {
		t.Fatalf("admin mutation error = %v", err)
	}

	select {
	case err := <-reloadDone:
		if err != nil {
			t.Fatalf("watcher reload error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher reload did not complete after admin mutation lock was released")
	}
}

func fetchKeyTypesForTest(t *testing.T, server *Signer) []signerapi.KeyTypeInfo {
	t.Helper()

	w := httptest.NewRecorder()
	server.handleKeyTypes(w, requestWithIdentity(http.MethodGet, "/keytypes", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/keytypes failed: %d: %s", w.Code, w.Body.String())
	}

	var resp signerapi.KeyTypesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /keytypes response: %v", err)
	}

	return resp.KeyTypes
}

func findKeyTypeInfo(keyTypes []signerapi.KeyTypeInfo, keyType string) (signerapi.KeyTypeInfo, bool) {
	for _, info := range keyTypes {
		if info.KeyType == keyType {
			return info, true
		}
	}
	return signerapi.KeyTypeInfo{}, false
}

func saveGenericTemplateForTest(t *testing.T, server *Signer, keyType string, yamlData []byte) {
	t.Helper()

	ir := server.productRuntime()
	err := ir.WithKeyring(func(masterKey *crypto.Keyring) error {
		active, err := ir.ActivePaths()
		if err != nil {
			return err
		}
		_, err = templatestore.SaveTemplateActive(active, yamlData, keyType, templatestore.TemplateTypeGeneric, masterKey)
		return err
	})
	if err != nil {
		t.Fatalf("SaveTemplate(%q) error = %v", keyType, err)
	}
	activeKeyPaths, err := ir.ActiveKeyPaths()
	if err != nil {
		t.Fatalf("ActiveKeyPaths(%q) error = %v", keyType, err)
	}
	if err := keytypestate.Put(activeKeyPaths, keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceYAMLGeneric,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("keytypestate.Put(%q) error = %v", keyType, err)
	}
}

func registerGenericTemplateProviderForTest(t *testing.T, yamlData []byte) {
	t.Helper()

	spec, err := generictemplate.ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() error = %v", err)
	}
	if !genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec)) {
		t.Fatalf("template %q already registered", spec.KeyType())
	}
}

func reloadKeysWithTemplatesForTest(server *Signer) error {
	ir := server.productRuntime()
	if ir == nil {
		return fmt.Errorf("identity not found")
	}
	_, err := ir.Reload()
	return err
}

func renderGenericTemplateYAML(family string, version int, displayName, description string) []byte {
	return []byte(fmt.Sprintf(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: %s
version: %d
display_name: %q
description: %q
max_opcode_cost: 20000
teal: |
  #pragma version 8
  int 1
`, family, version, displayName, description))
}
