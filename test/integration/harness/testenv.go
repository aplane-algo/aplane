// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package harness

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"gopkg.in/yaml.v3"
)

// TestEnvCloneOptions controls how the shared /tmp integration environment is cloned.
type TestEnvCloneOptions struct {
	UserAutoApprove  *bool
	LockOnDisconnect *bool
}

// TestEnvClone holds per-test copies of the shared signer/client integration data dirs.
type TestEnvClone struct {
	SignerDataDir string
	ClientDataDir string
}

// CloneSharedTestEnv copies the shared /tmp integration environment into a per-test temp dir,
// clears copied key files, applies requested config overrides, and exports APSIGNER_DATA/APCLIENT_DATA.
func CloneSharedTestEnv(t *testing.T, opts TestEnvCloneOptions) *TestEnvClone {
	t.Helper()

	signerSrc := firstExistingDir(
		os.Getenv("APLANE_SHARED_APSIGNER_DATA"),
		"/tmp/aplane-test-env/apadmin",
		os.Getenv("APSIGNER_DATA"),
	)
	clientSrc := firstExistingDir(
		os.Getenv("APLANE_SHARED_APCLIENT_DATA"),
		"/tmp/aplane-test-env/apclient",
		os.Getenv("APCLIENT_DATA"),
	)
	if signerSrc == "" {
		t.Fatal("no signer test environment source found")
	}
	if clientSrc == "" {
		t.Fatal("no client test environment source found")
	}

	root := mustMakeShortTempDir(t, "apl-it-")
	signerDst := filepath.Join(root, "apadmin")
	clientDst := filepath.Join(root, "apclient")

	if err := copyDir(signerSrc, signerDst); err != nil {
		t.Fatalf("failed to clone signer test env from %s: %v", signerSrc, err)
	}
	if err := copyDir(clientSrc, clientDst); err != nil {
		t.Fatalf("failed to clone client test env from %s: %v", clientSrc, err)
	}
	if err := assignClonedPorts(signerDst, clientDst); err != nil {
		t.Fatalf("failed to assign cloned ports: %v", err)
	}
	if err := ensureClonedClientSSH(clientSrc, clientDst); err != nil {
		t.Fatalf("failed to seed cloned client SSH keys: %v", err)
	}
	if err := clearClonedSignerKeys(signerDst); err != nil {
		t.Fatalf("failed to clear cloned signer keys: %v", err)
	}
	if err := syncClonedSSHAuthorization(signerDst, clientDst); err != nil {
		t.Fatalf("failed to sync cloned SSH authorization: %v", err)
	}
	if err := syncClonedKnownHosts(signerDst, clientDst); err != nil {
		t.Fatalf("failed to sync cloned known_hosts: %v", err)
	}
	if opts.UserAutoApprove != nil {
		if err := setSignerUserAutoApprove(signerDst, *opts.UserAutoApprove); err != nil {
			t.Fatalf("failed to update cloned signer config: %v", err)
		}
	}
	if opts.LockOnDisconnect != nil {
		if err := setSignerLockOnDisconnect(signerDst, *opts.LockOnDisconnect); err != nil {
			t.Fatalf("failed to update cloned signer disconnect policy: %v", err)
		}
	}

	t.Setenv("APSIGNER_DATA", signerDst)
	t.Setenv("APCLIENT_DATA", clientDst)
	t.Setenv("APLANE_SHARED_APSIGNER_DATA", signerSrc)
	t.Setenv("APLANE_SHARED_APCLIENT_DATA", clientSrc)

	passphrasePath := filepath.Join(signerDst, "passphrase")
	data, err := os.ReadFile(passphrasePath)
	if err != nil {
		t.Fatalf("failed to read cloned signer passphrase %s: %v", passphrasePath, err)
	}
	t.Setenv("TEST_PASSPHRASE", strings.TrimSpace(string(data)))

	return &TestEnvClone{
		SignerDataDir: signerDst,
		ClientDataDir: clientDst,
	}
}

func firstExistingDir(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(srcPath)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, dstPath); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			// Skip runtime artifacts such as sockets copied from the shared /tmp env.
			continue
		}

		data, err := os.ReadFile(srcPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dstPath, data, info.Mode()); err != nil {
			return err
		}
	}

	return nil
}

func clearClonedSignerKeys(dataDir string) error {
	keysDir := filepath.Join(dataDir, "identities", "default", "keys")
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".key") {
			if err := os.Remove(filepath.Join(keysDir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func mustMakeShortTempDir(t *testing.T, prefix string) string {
	t.Helper()

	base := secureIntegrationTempBase(t)
	root, err := os.MkdirTemp(base, prefix)
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func secureIntegrationTempBase(t *testing.T) string {
	t.Helper()

	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Fatalf("failed to find project root: %v", err)
	}
	base := filepath.Join(projectRoot, "temp", "integration")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatalf("failed to create integration temp base: %v", err)
	}
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatalf("failed to secure integration temp base: %v", err)
	}
	return base
}

func syncClonedSSHAuthorization(signerDataDir, clientDataDir string) error {
	clientPubPath := filepath.Join(clientDataDir, ".ssh", "id_ed25519.pub")
	pubKey, err := os.ReadFile(clientPubPath)
	if err != nil {
		return err
	}

	identitySSHDir := filepath.Join(signerDataDir, "identities", "default", ".ssh")
	if err := os.MkdirAll(identitySSHDir, 0700); err != nil {
		return err
	}

	identityAuthPath := filepath.Join(identitySSHDir, "authorized_keys")
	if err := os.WriteFile(identityAuthPath, pubKey, 0600); err != nil {
		return err
	}

	legacyAuthPath := filepath.Join(signerDataDir, ".ssh", "authorized_keys")
	if err := os.WriteFile(legacyAuthPath, pubKey, 0600); err != nil {
		return err
	}

	return nil
}

func ensureClonedClientSSH(clientSrc, clientDst string) error {
	dstSSH := filepath.Join(clientDst, ".ssh")
	pubPath := filepath.Join(dstSSH, "id_ed25519.pub")
	if _, err := os.Stat(pubPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	candidates := []string{
		filepath.Join(clientSrc, ".ssh"),
		filepath.Join(os.Getenv("APLANE_SHARED_APCLIENT_DATA"), ".ssh"),
		"/tmp/aplane-test-env/apclient/.ssh",
	}
	for _, srcSSH := range candidates {
		if srcSSH == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(srcSSH, "id_ed25519.pub")); err != nil {
			continue
		}
		return copyDir(srcSSH, dstSSH)
	}
	return fmt.Errorf("no source client SSH keys found for clone")
}

func syncClonedKnownHosts(signerDataDir, clientDataDir string) error {
	hostPubPath := filepath.Join(signerDataDir, ".ssh", "ssh_host_key.pub")
	pubKey, err := os.ReadFile(hostPubPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	clientCfgPath := filepath.Join(clientDataDir, "config.yaml")
	data, err := os.ReadFile(clientCfgPath)
	if err != nil {
		return err
	}
	var cfg struct {
		SSH struct {
			Host string `yaml:"host"`
			Port int    `yaml:"port"`
		} `yaml:"ssh"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if cfg.SSH.Host == "" || cfg.SSH.Port == 0 {
		return fmt.Errorf("client ssh config missing host/port")
	}

	knownHostsDir := filepath.Join(clientDataDir, ".ssh")
	if err := os.MkdirAll(knownHostsDir, 0o700); err != nil {
		return err
	}
	entry := fmt.Sprintf("[%s]:%d %s\n", cfg.SSH.Host, cfg.SSH.Port, strings.TrimSpace(string(pubKey)))
	return os.WriteFile(filepath.Join(knownHostsDir, "known_hosts"), []byte(entry), 0o600)
}

func setSignerUserAutoApprove(dataDir string, userAutoApprove bool) error {
	if err := setSignerBoolConfig(dataDir, "user_auto_approve", userAutoApprove); err != nil {
		return err
	}
	return identity.SaveStoredSetting(dataDir, "default", "user_auto_approve", userAutoApprove)
}

func setSignerLockOnDisconnect(dataDir string, lockOnDisconnect bool) error {
	if err := setSignerBoolConfig(dataDir, "lock_on_disconnect", lockOnDisconnect); err != nil {
		return err
	}
	return identity.SaveStoredSetting(dataDir, "default", "lock_on_disconnect", lockOnDisconnect)
}

func setSignerBoolConfig(dataDir, key string, value bool) error {
	configPath := filepath.Join(dataDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg[key] = value

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, out, 0600)
}

func assignClonedPorts(signerDataDir, clientDataDir string) error {
	ports, err := reserveTCPPorts(2)
	if err != nil {
		return err
	}
	signerPort := ports[0]
	sshPort := ports[1]
	if err := setYAMLPath(filepath.Join(signerDataDir, "config.yaml"), signerPort, "signer_port"); err != nil {
		return err
	}
	if err := setYAMLPath(filepath.Join(signerDataDir, "config.yaml"), sshPort, "ssh", "port"); err != nil {
		return err
	}
	if err := setYAMLPath(filepath.Join(clientDataDir, "config.yaml"), signerPort, "signer_port"); err != nil {
		return err
	}
	return setYAMLPath(filepath.Join(clientDataDir, "config.yaml"), sshPort, "ssh", "port")
}

func reserveTCPPorts(count int) ([]int, error) {
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	ports := make([]int, 0, count)
	for range count {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

func setYAMLPath(path string, value interface{}, keys ...string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	current := cfg
	for _, key := range keys[:len(keys)-1] {
		next, ok := current[key].(map[string]interface{})
		if !ok {
			next = make(map[string]interface{})
			current[key] = next
		}
		current = next
	}
	current[keys[len(keys)-1]] = value

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0600)
}
