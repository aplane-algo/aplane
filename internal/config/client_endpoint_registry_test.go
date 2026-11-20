// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testCosignerOnlyRegistry = `schema_version: 2
endpoints:
  cos:
    role: cosigner
    url: ssh://cos.example
`
	testSignerRegistry = `schema_version: 2
endpoints:
  primary:
    role: signer
    url: ssh://signer.example
    identity_file: keys/id
  cos:
    role: cosigner
    url: ssh://cos.example:2223
`
	// What saving testSignerRegistry writes: yaml.v3's own layout, with the
	// relative identity_file kept and no path defaults filled in.
	testSignerRegistrySaved = `schema_version: 2
endpoints:
    cos:
        role: cosigner
        url: ssh://cos.example:2223
    primary:
        role: signer
        url: ssh://signer.example
        identity_file: keys/id
`
)

func writeTestEndpointRegistry(t *testing.T, contents string) string {
	t.Helper()
	dataDir := t.TempDir()
	if err := os.WriteFile(GetClientEndpointsPath(dataDir), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return dataDir
}

func readTestEndpointRegistry(t *testing.T, dataDir string) string {
	t.Helper()
	data, err := os.ReadFile(GetClientEndpointsPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A registry loads the same way for runtime use and for editing, and
// re-saving what was loaded writes the stored form. The signer endpoint is
// the one whose role is signer; nothing else names it.
func TestClientEndpointRegistryLoadAndSave(t *testing.T) {
	tests := []struct {
		name       string
		contents   string
		wantSigner string
		wantSaved  string
	}{
		{
			name:     "no signer",
			contents: testCosignerOnlyRegistry,
			wantSaved: `schema_version: 2
endpoints:
    cos:
        role: cosigner
        url: ssh://cos.example
`,
		},
		{name: "signer", contents: testSignerRegistry, wantSigner: "primary", wantSaved: testSignerRegistrySaved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := writeTestEndpointRegistry(t, tt.contents)

			runtime, err := LoadClientEndpointRegistry(dataDir)
			if err != nil {
				t.Fatalf("LoadClientEndpointRegistry() error = %v", err)
			}
			alias, endpoint, ok := runtime.SignerEndpoint()
			if alias != tt.wantSigner || ok != (tt.wantSigner != "") {
				t.Fatalf("runtime SignerEndpoint() = %q, %v; want %q", alias, ok, tt.wantSigner)
			}
			if ok && (endpoint.IdentityFile != filepath.Join(dataDir, "keys/id") ||
				endpoint.KnownHostsPath != filepath.Join(dataDir, ".ssh/known_hosts")) {
				t.Fatalf("runtime signer endpoint paths = %q, %q; want resolved against the data dir", endpoint.IdentityFile, endpoint.KnownHostsPath)
			}
			if cos := runtime.Endpoints["cos"]; cos.IdentityFile != filepath.Join(dataDir, ".ssh/id_ed25519") {
				t.Fatalf("runtime cosigner identity_file = %q, want the resolved default", cos.IdentityFile)
			}

			stored, err := LoadStoredClientEndpointRegistry(dataDir)
			if err != nil {
				t.Fatalf("LoadStoredClientEndpointRegistry() error = %v", err)
			}
			if alias, _, _ := stored.SignerEndpoint(); alias != tt.wantSigner {
				t.Fatalf("stored SignerEndpoint() = %q, want %q", alias, tt.wantSigner)
			}
			if cos := stored.Endpoints["cos"]; cos.IdentityFile != "" || cos.KnownHostsPath != "" {
				t.Fatalf("stored cosigner paths = %q, %q; want them left unset", cos.IdentityFile, cos.KnownHostsPath)
			}
			if err := SaveStoredClientEndpointRegistry(dataDir, stored); err != nil {
				t.Fatalf("SaveStoredClientEndpointRegistry() error = %v", err)
			}
			if got := readTestEndpointRegistry(t, dataDir); got != tt.wantSaved {
				t.Fatalf("saved endpoints.yaml =\n%s\nwant\n%s", got, tt.wantSaved)
			}
		})
	}
}

// The registry has no default field. A file that earlier releases wrote with
// one is refused by the strict decode until the line is removed.
func TestClientEndpointRegistryRefusesDefaultField(t *testing.T) {
	dataDir := writeTestEndpointRegistry(t, "schema_version: 2\ndefault: primary\n"+strings.TrimPrefix(testSignerRegistry, "schema_version: 2\n"))
	want := "failed to parse " + GetClientEndpointsPath(dataDir) + ": yaml: unmarshal errors:\n" +
		"  line 2: field default not found in type config.ClientEndpointRegistry"
	if _, err := LoadClientEndpointRegistry(dataDir); err == nil || err.Error() != want {
		t.Fatalf("LoadClientEndpointRegistry() error = %v, want %q", err, want)
	}
	if _, err := LoadStoredClientEndpointRegistry(dataDir); err == nil || err.Error() != want {
		t.Fatalf("LoadStoredClientEndpointRegistry() error = %v, want %q", err, want)
	}
}

// Both loaders refuse the same files with the same error.
func TestClientEndpointRegistryLoadRefusals(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		wantErr  string
	}{
		{
			name:     "two signers",
			contents: "schema_version: 2\nendpoints:\n  a:\n    role: signer\n    url: ssh://a.example\n  b:\n    role: signer\n    url: ssh://b.example\n",
			wantErr:  `endpoints.yaml may contain at most one "signer" endpoint`,
		},
		{
			name:     "missing role",
			contents: "schema_version: 2\nendpoints:\n  a:\n    url: ssh://a.example\n",
			wantErr:  `endpoint "a": role is required (expected "signer" or "cosigner")`,
		},
		{
			name:     "invalid alias",
			contents: "schema_version: 2\nendpoints:\n  bad/alias:\n    role: cosigner\n    url: ssh://a.example\n",
			wantErr:  `endpoint "bad/alias": alias "bad/alias" must contain only ASCII letters, digits, '.', '_', or '-'`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := writeTestEndpointRegistry(t, tt.contents)
			loaders := map[string]func(string) (ClientEndpointRegistry, error){
				"LoadClientEndpointRegistry":       LoadClientEndpointRegistry,
				"LoadStoredClientEndpointRegistry": LoadStoredClientEndpointRegistry,
			}
			for name, load := range loaders {
				_, err := load(dataDir)
				if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr) {
					t.Errorf("%s() error = %v, want %q", name, err, tt.wantErr)
				}
			}
		})
	}
}

// The signer endpoint cannot be deleted; anything else can, and the file is
// written only when something is.
func TestRemoveStoredClientEndpointRefusesSignerAlias(t *testing.T) {
	dataDir := writeTestEndpointRegistry(t, testSignerRegistry)

	err := RemoveStoredClientEndpoint(dataDir, "primary")
	if err == nil || err.Error() != `endpoint alias "primary" is the signer endpoint` {
		t.Fatalf("RemoveStoredClientEndpoint(primary) error = %v", err)
	}
	if got := readTestEndpointRegistry(t, dataDir); got != testSignerRegistry {
		t.Fatalf("a refused delete rewrote endpoints.yaml:\n%s", got)
	}
	err = RemoveStoredClientEndpoint(dataDir, "missing")
	if err == nil || err.Error() != `endpoint alias "missing" is not defined` {
		t.Fatalf("RemoveStoredClientEndpoint(missing) error = %v", err)
	}
	if err := RemoveStoredClientEndpoint(dataDir, "cos"); err != nil {
		t.Fatalf("RemoveStoredClientEndpoint(cos) error = %v", err)
	}
	want := `schema_version: 2
endpoints:
    primary:
        role: signer
        url: ssh://signer.example
        identity_file: keys/id
`
	if got := readTestEndpointRegistry(t, dataDir); got != want {
		t.Fatalf("endpoints.yaml after deleting cos =\n%s\nwant\n%s", got, want)
	}
}

// Adding and removing endpoints one at a time, as the shell's commands do:
// each plan says what became of the alias, and the file holds the result.
func TestStoredClientEndpointAddAndRemove(t *testing.T) {
	dataDir := t.TempDir()
	type flags struct{ created, updated, destinationChanged bool }
	steps := []struct {
		alias    string
		endpoint ClientEndpointConfig
		want     flags
	}{
		{"cos", ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: " ssh://cos.example/ "}, flags{created: true}},
		{"primary", ClientEndpointConfig{Role: ClientEndpointRoleSigner, URL: "ssh://signer.example"}, flags{created: true}},
		{"primary", ClientEndpointConfig{Role: ClientEndpointRoleSigner, URL: "ssh://signer.example"}, flags{}},
		{"primary", ClientEndpointConfig{Role: ClientEndpointRoleSigner, URL: "ssh://signer.example:2200"}, flags{updated: true, destinationChanged: true}},
		{"cos", ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://cos.example", IdentityFile: "other/id"}, flags{updated: true}},
	}
	for i, step := range steps {
		plan, err := PlanStoredClientEndpointUpsert(dataDir, step.alias, step.endpoint, true)
		if err != nil {
			t.Fatalf("step %d: PlanStoredClientEndpointUpsert(%s) error = %v", i, step.alias, err)
		}
		got := flags{plan.Created, plan.Updated, plan.DestinationChanged}
		if got != step.want {
			t.Fatalf("step %d: plan flags = %+v, want %+v", i, got, step.want)
		}
		if err := SaveStoredClientEndpointRegistry(dataDir, plan.Registry); err != nil {
			t.Fatalf("step %d: SaveStoredClientEndpointRegistry() error = %v", i, err)
		}
	}
	want := `schema_version: 2
endpoints:
    cos:
        role: cosigner
        url: ssh://cos.example
        identity_file: other/id
    primary:
        role: signer
        url: ssh://signer.example:2200
`
	if got := readTestEndpointRegistry(t, dataDir); got != want {
		t.Fatalf("endpoints.yaml after adds =\n%s\nwant\n%s", got, want)
	}

	if err := RemoveStoredClientEndpoint(dataDir, "cos"); err != nil {
		t.Fatalf("RemoveStoredClientEndpoint(cos) error = %v", err)
	}
	want = `schema_version: 2
endpoints:
    primary:
        role: signer
        url: ssh://signer.example:2200
`
	if got := readTestEndpointRegistry(t, dataDir); got != want {
		t.Fatalf("endpoints.yaml after removing cos =\n%s\nwant\n%s", got, want)
	}
}

// The URL rules for a client endpoint record, on the save path (a plan, as
// endpoints add, create and import make) and the load path. Accepted URLs
// are stored without surrounding space or a trailing slash.
func TestClientEndpointURLRules(t *testing.T) {
	tests := []struct {
		raw      string
		wantURL  string
		wantErr  string // after the alias prefix
		wantHost string
		wantPort int
	}{
		{raw: "ssh://signer.example", wantURL: "ssh://signer.example", wantHost: "signer.example", wantPort: DefaultSSHPort},
		{raw: "ssh://signer.example:2223", wantURL: "ssh://signer.example:2223", wantHost: "signer.example", wantPort: 2223},
		{raw: " ssh://signer.example:2223/ ", wantURL: "ssh://signer.example:2223", wantHost: "signer.example", wantPort: 2223},
		{raw: "SSH://signer.example", wantURL: "SSH://signer.example", wantHost: "signer.example", wantPort: DefaultSSHPort},
		{raw: "ssh://user@signer.example", wantURL: "ssh://user@signer.example", wantHost: "signer.example", wantPort: DefaultSSHPort},
		{raw: "ssh://[::1]:2223", wantURL: "ssh://[::1]:2223", wantHost: "::1", wantPort: 2223},
		{raw: "ssh://127.0.0.1:65535", wantURL: "ssh://127.0.0.1:65535", wantHost: "127.0.0.1", wantPort: 65535},
		{raw: "ssh://signer.example:0", wantErr: `invalid url port "0"`},
		{raw: "ssh://signer.example:65536", wantErr: `invalid url port "65536"`},
		{raw: "ssh://signer.example:abc", wantErr: `invalid url: parse "ssh://signer.example:abc": invalid port ":abc" after host`},
		{raw: "ssh://", wantErr: "url host is required"},
		{raw: "ssh:///path", wantErr: "url host is required"},
		{raw: "https://signer.example", wantErr: `unsupported url scheme "https"; endpoints are ssh://host[:port]`},
		{raw: "http://127.0.0.1:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "http://signer.example:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "ftp://signer.example", wantErr: `unsupported url scheme "ftp"; endpoints are ssh://host[:port]`},
		{raw: "self", wantErr: `unsupported url scheme ""; endpoints are ssh://host[:port]`},
		{raw: "", wantErr: "url is required"},
		{raw: "://bad", wantErr: `invalid url: parse "://bad": missing protocol scheme`},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			plan, err := PlanStoredClientEndpointUpsert(t.TempDir(), "e", ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: tt.raw}, false)
			checkEndpointURLResult(t, "save", err, plan.Endpoint.URL, tt.wantURL, tt.wantErr)

			dataDir := writeTestEndpointRegistry(t, fmt.Sprintf("schema_version: 2\nendpoints:\n  e:\n    role: cosigner\n    url: %q\n", tt.raw))
			registry, err := LoadClientEndpointRegistry(dataDir)
			checkEndpointURLResult(t, "load", err, registry.Endpoints["e"].URL, tt.wantURL, tt.wantErr)

			if tt.wantErr != "" {
				return
			}
			host, port, err := ClientEndpointSSHHostPort(registry.Endpoints["e"])
			if err != nil || host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("ClientEndpointSSHHostPort() = %q, %d, %v; want %q, %d", host, port, err, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func checkEndpointURLResult(t *testing.T, path string, err error, gotURL, wantURL, wantErr string) {
	t.Helper()
	if wantErr != "" {
		if err == nil || err.Error() != `endpoint "e": `+wantErr {
			t.Fatalf("%s path error = %v, want %q", path, err, wantErr)
		}
		return
	}
	if err != nil || gotURL != wantURL {
		t.Fatalf("%s path = %q, %v; want %q", path, gotURL, err, wantURL)
	}
}

// ClientEndpointSSHHostPort refuses a record that never passed the URL
// rules, as an in-memory registry may hold.
func TestClientEndpointSSHHostPortRefusesUnvalidatedURLs(t *testing.T) {
	tests := map[string]string{
		"https://signer.example":     `endpoint URL "https://signer.example": unsupported url scheme "https"; endpoints are ssh://host[:port]`,
		"ssh://":                     `endpoint URL "ssh://": url host is required`,
		"ssh://signer.example:0":     `endpoint URL "ssh://signer.example:0": invalid url port "0"`,
		"ssh://signer.example:99999": `endpoint URL "ssh://signer.example:99999": invalid url port "99999"`,
		"://bad":                     `endpoint URL "://bad": invalid url: parse "://bad": missing protocol scheme`,
	}
	for raw, want := range tests {
		if _, _, err := ClientEndpointSSHHostPort(ClientEndpointConfig{URL: raw}); err == nil || err.Error() != want {
			t.Errorf("ClientEndpointSSHHostPort(%q) error = %v, want %q", raw, err, want)
		}
	}
}
