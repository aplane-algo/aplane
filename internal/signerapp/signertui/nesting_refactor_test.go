// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/lsigprovider"
)

// A parameter's selected input mode decides what is sent for it: the value
// as typed, or its hash, taken over the text or over the bytes its hex names.
func TestInputModeTransforms(t *testing.T) {
	sum256 := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	sum512 := func(b []byte) string { h := sha512.Sum512_256(b); return hex.EncodeToString(h[:]) }
	modes := []lsigprovider.InputMode{
		{Name: "text256", Transform: "sha256", InputType: "string"},
		{Name: "hex256", Transform: "sha256"},
		{Name: "text512", Transform: "sha512_256", InputType: "string"},
		{Name: "hex512", Transform: "sha512_256", InputType: "hex"},
		{Name: "as typed"},
		{Name: "unknown", Transform: "md5", InputType: "string"},
	}
	tests := []struct {
		name    string
		value   string
		mode    int
		noModes bool
		want    string
		wantErr string
	}{
		{name: "sha256 of text", value: "abc", mode: 0, want: sum256([]byte("abc"))},
		{name: "sha256 of hex bytes", value: "616263", mode: 1, want: sum256([]byte("abc"))},
		{name: "sha512/256 of text", value: "abc", mode: 2, want: sum512([]byte("abc"))},
		{name: "sha512/256 of hex bytes", value: "616263", mode: 3, want: sum512([]byte("abc"))},
		{name: "text that is also hex is hashed as text", value: "616263", mode: 0, want: sum256([]byte("616263"))},
		{name: "bad hex is refused", value: "xyz", mode: 1, wantErr: "p: invalid hex input for hex256 mode"},
		{name: "bad hex is refused for sha512/256", value: "abc", mode: 3, wantErr: "p: invalid hex input for hex512 mode"},
		{name: "an empty value stays empty", value: "", mode: 0, want: ""},
		{name: "an empty hex value stays empty", value: "", mode: 3, want: ""},
		{name: "a mode with no transform sends the value as typed", value: "abcd", mode: 4, want: "abcd"},
		{name: "an unknown transform sends the value as typed", value: "abcd", mode: 5, want: "abcd"},
		{name: "a mode past the end sends the value as typed", value: "abcd", mode: len(modes), want: "abcd"},
		{name: "a negative mode sends the value as typed", value: "abcd", mode: -1, want: "abcd"},
		{name: "a parameter with no modes sends the value as typed", value: "abcd", mode: 0, noModes: true, want: "abcd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Model{forms: formsState{
				genericLSigParams:     map[string]string{"p": tt.value, "after": "aabb"},
				genericLSigParamModes: map[string]int{"p": tt.mode},
			}}
			param := lsigprovider.ParameterDef{Name: "p", Type: "bytes", InputModes: modes}
			if tt.noModes {
				param.InputModes = nil
			}
			got, err := m.applyInputModeTransforms([]lsigprovider.ParameterDef{param, {Name: "after", Type: "bytes"}})
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr || got != nil {
					t.Fatalf("got %v, error %v; want error %q", got, err, tt.wantErr)
				}
				return
			}
			// The parameter after it is always still collected.
			if want := map[string]string{"p": tt.want, "after": "aabb"}; err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v, error %v; want %v", got, err, want)
			}
		})
	}
}

// The popup shown while a key type is enabled or disabled names which.
func TestTemplateInstallingTitle(t *testing.T) {
	tests := []struct {
		name    string
		pending *LibraryTemplateInfo
		want    string
	}{
		{"nothing pending", nil, "Enabling Template Key Type"},
		{"a template not yet installed", &LibraryTemplateInfo{KeyType: "pub.t.v1"}, "Enabling Template Key Type"},
		{"an installed, disabled template", &LibraryTemplateInfo{KeyType: "pub.t.v1", Installed: true}, "Enabling Template Key Type"},
		{"an installed, enabled template", &LibraryTemplateInfo{KeyType: "pub.t.v1", Installed: true, Enabled: true}, "Disabling Template Key Type"},
		{"an enabled flag on a template not installed", &LibraryTemplateInfo{KeyType: "pub.t.v1", Enabled: true}, "Enabling Template Key Type"},
		{"a compiled key type not enabled", &LibraryTemplateInfo{KeyType: "pub.c.v1", TemplateType: libraryTypeCompiledProvider}, "Enabling Key Type"},
		{"a compiled key type enabled", &LibraryTemplateInfo{KeyType: "pub.c.v1", TemplateType: libraryTypeCompiledProvider, Installed: true}, "Disabling Key Type"},
		{"a compiled key type with only the enabled flag", &LibraryTemplateInfo{KeyType: "pub.c.v1", TemplateType: libraryTypeCompiledProvider, Enabled: true}, "Enabling Key Type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Model{width: 100, height: 30}
			m.library.pendingTemplate = tt.pending
			view := m.renderTemplateInstalling()
			found := ""
			for _, title := range []string{"Disabling Template Key Type", "Enabling Template Key Type", "Disabling Key Type", "Enabling Key Type"} {
				if strings.Contains(view, title) {
					found = title
					break
				}
			}
			if found != tt.want {
				t.Fatalf("title = %q, want %q:\n%s", found, tt.want, view)
			}
		})
	}
}
