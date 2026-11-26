// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/templatespec"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// A template install whose reload fails registers nothing: the reload
// registers a template only when it publishes it. Its rollback removes what
// the install wrote and unregisters nothing, so a provider registered under
// the key type before the install stays registered. The rollback once
// unregistered every key type it rolled back, that provider included.
func TestAFailedTemplateInstallRegistersNothingAndKeepsAnEarlierProvider(t *testing.T) {
	t.Run("nothing registered", func(t *testing.T) {
		server, cleanup := setupTestSigner(t)
		defer cleanup()
		family := fmt.Sprintf("in-place-install-%d", time.Now().UnixNano())
		keyType := testTemplateKeyType(family)
		writeLibraryTemplateForTest(t, server, "install.yaml", renderGenericTemplateYAML(family, 1, "Install", "a reload that fails"))
		failBuildKeepingTheView(server, errors.New("forced build failure"))

		result := server.adminServices().templateApp().InstallLibraryTemplate(adminproto.InstallLibraryTemplateRequest{
			KeyType: keyType, TemplateType: string(templatespec.TemplateTypeGeneric),
		})
		if result.Success || result.Code != protocol.ResultCodeReloadFailed {
			t.Fatalf("InstallLibraryTemplate() = %+v, want reload_failed", result)
		}
		if lsigprovider.Get(keyType) != nil {
			t.Fatal("a template install whose reload failed registered its provider")
		}
		assertInstalledTemplateRemoved(t, server, keyType, templatespec.TemplateTypeGeneric)
	})
	t.Run("an earlier provider stays", func(t *testing.T) {
		server, cleanup := setupTestSigner(t)
		defer cleanup()
		family := fmt.Sprintf("in-place-earlier-%d", time.Now().UnixNano())
		keyType := testTemplateKeyType(family)
		yamlData := renderGenericTemplateYAML(family, 1, "Earlier", "registered before the install")
		writeLibraryTemplateForTest(t, server, "earlier.yaml", yamlData)
		spec, err := generictemplate.ParseTemplateSpec(yamlData)
		if err != nil {
			t.Fatal(err)
		}
		earlier := generictemplate.NewYAMLTemplate(spec)
		if !lsigprovider.RegisterIfAbsent(earlier) {
			t.Fatalf("template %q already registered", keyType)
		}
		t.Cleanup(func() { lsigprovider.Unregister(keyType) })
		failBuildKeepingTheView(server, errors.New("forced build failure"))

		result := server.adminServices().templateApp().InstallLibraryTemplate(adminproto.InstallLibraryTemplateRequest{
			KeyType: keyType, TemplateType: string(templatespec.TemplateTypeGeneric),
		})
		if result.Success || result.Code != protocol.ResultCodeReloadFailed || result.AlreadyExists {
			t.Fatalf("InstallLibraryTemplate() = %+v, want reload_failed for a new install", result)
		}
		if lsigprovider.Get(keyType) != earlier {
			t.Fatal("the rollback unregistered the provider registered before the install")
		}
	})
}

// A key deletion whose reload fails for a transient reason keeps the view in
// service, so the deleted key is still listed, but it cannot sign: every key
// load reads the key file, and the file is gone.
func TestADeletedKeyCannotSignAfterAFailedReload(t *testing.T) {
	server := characterizedSigner(t)
	ir := server.productRuntime()
	address := heldAddress(t, server)
	failBuildKeepingTheView(server, errors.New("forced build failure"))

	result := server.adminServices().keyApp().DeleteKey(context.Background(), adminproto.DeleteKeyRequest{Address: address})
	if result.Success || result.Code == protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("DeleteKey() = %+v, want a failed refresh with the view kept", result)
	}
	if !ir.IsUnlocked() || ir.KeyCount() != 1 {
		t.Fatalf("state %v with %d key(s), want the view in service kept", ir.GetState(), ir.KeyCount())
	}
	if key, err := ir.SnapshotKeySession().GetKeyWithContext(context.Background(), address); err == nil {
		if provider := coresigning.GetProviderForKey(key.Type, key.BaseKeyType); provider != nil {
			provider.ZeroKey(key)
		}
		t.Fatal("the deleted key still loads for signing")
	}
}

// A key type deactivation whose reload fails for a transient reason keeps
// the view in service, and still leaves no key of the type able to sign: a
// deactivation is refused while any aplane key of the type exists, the
// disabled template's provider is unregistered before the reload, and a key
// of the type is refused at generation.
func TestADeactivationWhoseReloadFailsLeavesTheTypeUnusable(t *testing.T) {
	server := characterizedSigner(t)
	importCharacterizedTemplate(t, server)
	keyType := testTemplateKeyType(characterizedFamily(server))
	t.Cleanup(func() { lsigprovider.Unregister(keyType) })
	failBuildKeepingTheView(server, errors.New("forced build failure"))

	result := server.adminServices().templateServices().DeactivateKeyType(adminproto.DeactivateKeyTypeRequest{KeyType: keyType})
	if result.Success || result.Code != protocol.ResultCodeReloadFailed {
		t.Fatalf("DeactivateKeyType() = %+v, want reload_failed", result)
	}
	if lsigprovider.Get(keyType) != nil {
		t.Fatal("the deactivated template's provider is still registered")
	}
	// The reload works again, so only the deactivation refuses the key.
	signerstartup.WireReloadFunc(server.productRuntime(), testProductBuildOptions(server), server.productBuildHooks())
	generated := server.adminServices().keyApp().GenerateKey(context.Background(), adminproto.GenerateKeyRequest{KeyType: keyType})
	if generated.Success || !strings.Contains(generated.Error, "is not enabled on this node") {
		t.Fatalf("GenerateKey(%s) = %+v after the deactivation, want it refused as not enabled", keyType, generated)
	}
}
