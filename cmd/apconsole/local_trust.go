// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var localSignerHostKeyProbe = probeLoopbackSignerHostKey

// readSignerHostKey reads the signer's SSH host key file. Tests replace it to
// watch the bytes read.
var readSignerHostKey = os.ReadFile

const (
	// localSignerProbeStartupWait is how long the probe keeps retrying a
	// refused connection when the console has just started the daemon.
	localSignerProbeStartupWait   = 3 * time.Second
	localSignerProbeRetryInterval = 50 * time.Millisecond
)

// trustLocalSignerHostKey records the local signer's SSH host key in the
// client's known_hosts after probing the listener for it. refusedWait is how
// long a refused connection is retried; zero fails at once.
func trustLocalSignerHostKey(clientDataDir string, signerCfg serverconfig.ServerConfig, refusedWait time.Duration) (string, error) {
	clientCfg, err := config.LoadConfig(clientDataDir)
	if err != nil {
		return "", fmt.Errorf("load client config: %w", err)
	}
	registry := clientCfg.ClientEndpointsOrDefault()
	_, endpoint, ok := registry.SignerEndpoint()
	if !ok {
		return "", nil
	}
	host, sshPort, err := config.ClientEndpointSSHHostPort(endpoint)
	if err != nil {
		return "", nil
	}
	if !isLoopbackSSHHost(host) {
		return "", nil
	}
	knownHostsPath := endpoint.KnownHostsPath
	if knownHostsPath == "" {
		return "", nil
	}

	hostKey, err := loadSSHPublicKeyFromPrivateKey(signerCfg.Endpoint.SSH.HostKeyPath)
	if err != nil {
		return "", fmt.Errorf("load local signer SSH host key: %w", err)
	}
	if err := probeLocalSignerHostKey(host, sshPort, hostKey, refusedWait); err != nil {
		return "", err
	}

	address := knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(sshPort)))
	line := knownhosts.Line([]string{address}, hostKey)

	existing, _, err := fsutil.ReadRegularFile(knownHostsPath)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read known_hosts: %w", err)
	}
	updated, changed := updateKnownHostsForLoopback(existing, address, line)
	if !changed {
		return "", nil
	}

	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		return "", fmt.Errorf("create known_hosts directory: %w", err)
	}
	if err := fsutil.WriteFileDurable(knownHostsPath, updated); err != nil {
		return "", fmt.Errorf("write known_hosts: %w", err)
	}
	return fmt.Sprintf("trusted local signer SSH host key for %s", address), nil
}

// updateKnownHostsForLoopback ensures line is the sole plain single-host entry
// for address. Stale plain single-host entries for address are dropped;
// markers (@revoked, @cert-authority), hashed hosts (|1|...), multi-host
// lines, comments, blank lines, and entries for other hosts are kept verbatim.
func updateKnownHostsForLoopback(existing []byte, address, line string) ([]byte, bool) {
	content := string(existing)
	exactMatches := 0
	staleMatches := 0

	var kept strings.Builder
	kept.Grow(len(content) + len(line) + 2)

	for len(content) > 0 {
		rawLine := content
		if idx := strings.IndexByte(content, '\n'); idx >= 0 {
			rawLine = content[:idx+1]
			content = content[idx+1:]
		} else {
			content = ""
		}

		trimmedLine := strings.TrimRight(rawLine, "\r\n")
		if isPlainSingleHostKnownHostsLine(trimmedLine, address) {
			if trimmedLine == line {
				exactMatches++
			} else {
				staleMatches++
			}
			continue
		}
		kept.WriteString(rawLine)
	}

	if exactMatches == 1 && staleMatches == 0 {
		return nil, false
	}
	if kept.Len() > 0 && !strings.HasSuffix(kept.String(), "\n") {
		kept.WriteByte('\n')
	}
	kept.WriteString(line)
	kept.WriteByte('\n')
	return []byte(kept.String()), true
}

func isPlainSingleHostKnownHostsLine(trimmedLine, address string) bool {
	fields := strings.Fields(trimmedLine)
	if len(fields) < 3 {
		return false
	}
	hostField := fields[0]
	if hostField == "" {
		return false
	}
	switch hostField[0] {
	case '#', '@', '|':
		return false
	}
	if strings.ContainsAny(hostField, ",*?!") {
		return false
	}
	return strings.EqualFold(hostField, address)
}

// loadSSHPublicKeyFromPrivateKey returns the public half of the signer's SSH
// host key. The file holds only the private key, so it is read and parsed,
// and the bytes read are zeroed at once; the parsed signer's own copy is
// x/crypto/ssh's.
func loadSSHPublicKeyFromPrivateKey(path string) (ssh.PublicKey, error) {
	data, err := readSignerHostKey(path)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(data)
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	return signer.PublicKey(), nil
}

// probeLocalSignerHostKey runs the probe, retrying a refused connection until
// wait elapses: a daemon that is still starting has not opened its listener.
// Any other error, such as a host key mismatch, returns at once.
func probeLocalSignerHostKey(host string, port int, key ssh.PublicKey, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := localSignerHostKeyProbe(host, port, key)
		if err == nil || !errors.Is(err, syscall.ECONNREFUSED) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(localSignerProbeRetryInterval)
	}
}

func probeLoopbackSignerHostKey(host string, port int, expected ssh.PublicKey) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("probe local signer SSH host key at %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	var sawHostKey bool
	var hostKeyErr error
	cfg := &ssh.ClientConfig{
		User: "apconsole-local-host-key-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			sawHostKey = true
			if !bytes.Equal(key.Marshal(), expected.Marshal()) {
				hostKeyErr = fmt.Errorf("local signer SSH host key mismatch at %s", addr)
				return hostKeyErr
			}
			return nil
		},
		Timeout: 2 * time.Second,
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err == nil {
		go ssh.DiscardRequests(reqs)
		go func() {
			for ch := range chans {
				_ = ch.Reject(ssh.Prohibited, "host key probe")
			}
		}()
		_ = sshConn.Close()
		return nil
	}
	if hostKeyErr != nil {
		return hostKeyErr
	}
	if sawHostKey {
		return nil
	}
	return fmt.Errorf("probe local signer SSH host key at %s: %w", addr, err)
}

func isLoopbackSSHHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
