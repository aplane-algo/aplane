// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"io"
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

	hostPort := net.JoinHostPort(host, strconv.Itoa(sshPort))
	address := knownhosts.Normalize(hostPort)
	line := knownhosts.Line([]string{address}, hostKey)

	changed, err := pinLoopbackHostKey(knownHostsPath, address, line)
	if err != nil {
		return "", err
	}
	warnOtherTrustedHostKeys(knownHostsPath, hostPort, hostKey)
	if !changed {
		return "", nil
	}
	return fmt.Sprintf("trusted local signer SSH host key for %s", address), nil
}

// pinLoopbackHostKey makes line the only plain entry for address in
// known_hosts, and reports whether the file had to change. A symlink is
// followed, as apshell follows it, so the file both use is the one replaced.
func pinLoopbackHostKey(knownHostsPath, address, line string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o700); err != nil {
		return false, fmt.Errorf("create known_hosts directory: %w", err)
	}
	replaced, err := os.OpenFile(knownHostsPath, os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return false, fmt.Errorf("open known_hosts: %w", err)
	}
	defer func() { _ = replaced.Close() }()
	existing, err := io.ReadAll(replaced)
	if err != nil {
		return false, fmt.Errorf("read known_hosts: %w", err)
	}
	updated, changed := updateKnownHostsForLoopback(existing, address, line)
	if !changed {
		return false, nil
	}

	target, err := filepath.EvalSymlinks(knownHostsPath)
	if err != nil {
		return false, fmt.Errorf("resolve known_hosts: %w", err)
	}
	if err := fsutil.WriteFileDurable(target, updated); err != nil {
		return false, fmt.Errorf("write known_hosts: %w", err)
	}

	// apshell appends without a lock, so a key it saved during the write went
	// to the replaced file. Carry it over. One it opened the file for but has
	// yet to write is still lost, and apshell asks for that key again.
	late, err := io.ReadAll(replaced)
	if err != nil {
		return false, fmt.Errorf("read replaced known_hosts: %w", err)
	}
	if len(late) > 0 {
		if err := appendKnownHosts(target, late); err != nil {
			return false, fmt.Errorf("carry over known_hosts entries: %w", err)
		}
	}
	return true, nil
}

func appendKnownHosts(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// warnOtherTrustedHostKeys reports each known_hosts line that accepts a key
// other than hostKey for hostPort. Only plain lines naming the host alone are
// replaced, so a rotated-out key stays trusted on any other kind of line.
func warnOtherTrustedHostKeys(knownHostsPath, hostPort string, hostKey ssh.PublicKey) {
	accepts, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return // the shell reports a file it can't parse
	}
	// No line holds the all-zero key, so the mismatch lists every key accepted.
	noKey, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		return
	}
	var mismatch *knownhosts.KeyError
	if !errors.As(accepts(hostPort, &net.TCPAddr{}, noKey), &mismatch) {
		return
	}
	for _, known := range mismatch.Want {
		if !bytes.Equal(known.Key.Marshal(), hostKey.Marshal()) {
			logWarnf("%s line %d also trusts another SSH host key for the local signer at %s", known.Filename, known.Line, hostPort)
		}
	}
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

	for rawLine := range strings.Lines(content) {
		trimmedLine := strings.TrimRight(rawLine, "\r\n")
		fields := strings.Fields(trimmedLine)
		if len(fields) >= 3 && strings.EqualFold(fields[0], address) {
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
