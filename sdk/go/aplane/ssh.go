// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package aplane

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

// sshTunnel manages an SSH tunnel to the signer.
type sshTunnel struct {
	client   *ssh.Client
	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup
}

// connect establishes an SSH tunnel to the signer.
// Token is used as the SSH username for 2FA (token + public key).
// Returns the local port that forwards to the signer.
func (t *sshTunnel) connect(host string, sshPort, signerPort int, token, sshKeyPath string) (int, error) {
	// Load SSH private key
	keyData, err := os.ReadFile(sshKeyPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return 0, fmt.Errorf("failed to parse SSH key: %w", err)
	}

	// SSH config - token is the username for 2FA
	config := &ssh.ClientConfig{
		User: token,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: proper host key verification
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", host, sshPort)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to SSH server: %w", err)
	}
	t.client = client

	// Create local listener on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		client.Close()
		return 0, fmt.Errorf("failed to create local listener: %w", err)
	}
	t.listener = listener
	t.done = make(chan struct{})

	localPort := listener.Addr().(*net.TCPAddr).Port
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", signerPort)

	// Start accepting connections
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			localConn, err := listener.Accept()
			if err != nil {
				select {
				case <-t.done:
					return
				default:
					continue
				}
			}

			// Forward to remote
			remoteConn, err := client.Dial("tcp", remoteAddr)
			if err != nil {
				localConn.Close()
				continue
			}

			// Bidirectional copy
			go func() {
				defer localConn.Close()
				defer remoteConn.Close()
				go io.Copy(remoteConn, localConn)
				io.Copy(localConn, remoteConn)
			}()
		}
	}()

	return localPort, nil
}

// close closes the SSH tunnel.
func (t *sshTunnel) close() {
	if t.done != nil {
		close(t.done)
	}
	if t.listener != nil {
		t.listener.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	t.wg.Wait()
}
