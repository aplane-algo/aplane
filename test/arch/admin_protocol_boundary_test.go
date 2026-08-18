// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package arch_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	adminProtocolPackage  = modulePrefix + "/internal/protocol"
	adminDomainPackage    = modulePrefix + "/internal/adminproto"
	adminTransportPackage = modulePrefix + "/internal/transport"
)

var adminServicePackages = []string{
	"internal/signerapp/admin",
	"internal/signerapp/backupadmin",
	"internal/signerapp/keyadmin",
	"internal/signerapp/storeadmin",
	"internal/signerapp/templateadmin",
}

// TestAdminProtocolDependencyDirection keeps the external wire contract from
// acquiring signer implementation dependencies and keeps the client transport
// independent of signer-domain services.
func TestAdminProtocolDependencyDirection(t *testing.T) {
	imports := moduleImports(t)

	for _, imported := range imports[adminProtocolPackage] {
		if strings.HasPrefix(imported, modulePrefix+"/internal/signerapp") ||
			imported == adminDomainPackage || imported == adminTransportPackage {
			t.Errorf("internal/protocol imports %s: the compatibility-bearing wire contract must not depend on domain services, the server stack, or client transport", imported)
		}
	}
	for _, imported := range imports[adminTransportPackage] {
		if imported == adminDomainPackage || strings.HasPrefix(imported, modulePrefix+"/internal/signerapp") {
			t.Errorf("internal/transport imports %s: the client transport must depend on wire types, not signer-domain services", imported)
		}
	}
}

// TestAdminServicesUseProtocolCodesNotWireMessages permits signer services to
// originate stable coded errors while keeping JSON messages, envelopes,
// sensitive wire wrappers, and serialization helpers at the adapter.
func TestAdminServicesUseProtocolCodesNotWireMessages(t *testing.T) {
	root := repositoryRoot(t)
	for _, relative := range adminServicePackages {
		files, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", relative, err)
		}
		for _, entry := range files {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(root, filepath.FromSlash(relative), entry.Name())
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("ParseFile(%s): %v", path, err)
			}
			aliases := protocolImportAliases(parsed)
			ast.Inspect(parsed, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := selector.X.(*ast.Ident)
				if !ok || !aliases[ident.Name] {
					return true
				}
				if strings.HasPrefix(selector.Sel.Name, "ErrCode") ||
					strings.HasPrefix(selector.Sel.Name, "ResultCode") ||
					selector.Sel.Name == "WithCode" {
					return true
				}
				t.Errorf("%s uses protocol.%s: admin-domain services may originate stable coded errors but must not construct or consume wire messages", filepath.Join(relative, entry.Name()), selector.Sel.Name)
				return true
			})
		}
	}
}

func protocolImportAliases(file *ast.File) map[string]bool {
	aliases := make(map[string]bool)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != adminProtocolPackage {
			continue
		}
		name := "protocol"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		aliases[name] = true
	}
	return aliases
}

var retiredSignerAdminForwarders = map[string]bool{
	"BuildAdminSettings":      true,
	"UpdateAdminSetting":      true,
	"BuildPolicySnapshot":     true,
	"ReplacePolicy":           true,
	"ValidatePolicy":          true,
	"ListKeys":                true,
	"GetKeyDetails":           true,
	"GenerateKey":             true,
	"DeleteKey":               true,
	"ImportKey":               true,
	"BackupIdentity":          true,
	"ListBackups":             true,
	"DeleteBackup":            true,
	"BeginBackupImport":       true,
	"AppendBackupImport":      true,
	"CommitBackupImport":      true,
	"AbortBackupImport":       true,
	"ReadBackupChunk":         true,
	"PreviewRestore":          true,
	"ListLibraryTemplates":    true,
	"InstallLibraryTemplate":  true,
	"ListInstalledTemplates":  true,
	"ShowInstalledTemplate":   true,
	"ShowLibraryTemplate":     true,
	"ImportInstalledTemplate": true,
	"RemoveInstalledTemplate": true,
	"ActivateKeyType":         true,
	"DeactivateKeyType":       true,
}

// TestRetiredSignerAdminForwardersStayDeleted prevents the monolithic daemon
// facade from regaining methods that only delegate to an existing application
// service. Daemon-owned recovery and inspection operations are intentionally
// absent from this list.
func TestRetiredSignerAdminForwardersStayDeleted(t *testing.T) {
	root := filepath.Join(repositoryRoot(t), "internal", "signerapp", "daemon")
	files, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || !retiredSignerAdminForwarders[fn.Name.Name] {
				continue
			}
			if receiverTypeName(fn.Recv) == "signerAdminServices" {
				t.Errorf("%s reintroduces retired signerAdminServices.%s forwarding", entry.Name(), fn.Name.Name)
			}
		}
	}
}
