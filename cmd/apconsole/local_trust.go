// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var localSignerHostKeyProbe = probeLoopbackSignerHostKey

func trustLocalSignerHostKey(clientDataDir string, signerCfg serverconfig.ServerConfig) (string, error) {
	if err := config.CheckSupportedClientEndpointConfig(clientDataDir); err != nil {
		return "", err
	}
	clientCfg, err := config.LoadConfig(clientDataDir)
	if err != nil {
		return "", fmt.Errorf("load client config: %w", err)
	}
	registry := clientCfg.ClientEndpointsOrDefault()
	_, endpoint, ok := registry.DefaultEndpoint()
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

	hostKey, err := loadSSHPublicKeyFromPrivateKey(signerCfg.Endpoint.SSH.HostKeyPath)
	if err != nil {
		return "", fmt.Errorf("load local signer SSH host key: %w", err)
	}
	if localSignerHostKeyProbe != nil {
		if err := localSignerHostKeyProbe(host, sshPort, hostKey); err != nil {
			return "", err
		}
	}

	address := knownHostAddress(host, sshPort)
	line := knownhosts.Line([]string{address}, hostKey)
	knownHostsPath := endpoint.KnownHostsPath
	if knownHostsPath == "" {
		return "", nil
	}

	if existing, err := os.ReadFile(knownHostsPath); err == nil {
		for _, existingLine := range splitKnownHostLines(string(existing)) {
			if existingLine == line {
				return "", nil
			}
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read known_hosts: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		return "", fmt.Errorf("create known_hosts directory: %w", err)
	}
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("open known_hosts: %w", err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write known_hosts: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close known_hosts: %w", err)
	}
	if err := os.Chmod(knownHostsPath, 0o600); err != nil {
		return "", fmt.Errorf("chmod known_hosts: %w", err)
	}
	return fmt.Sprintf("trusted local signer SSH host key for %s", address), nil
}

func loadSSHPublicKeyFromPrivateKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	return signer.PublicKey(), nil
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

func knownHostAddress(host string, port int) string {
	if port == 22 {
		return host
	}
	return "[" + host + "]:" + fmt.Sprint(port)
}

func splitKnownHostLines(data string) []string {
	var lines []string
	start := 0
	for i, r := range data {
		if r == '\n' {
			if line := data[start:i]; line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
