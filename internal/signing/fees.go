// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"net/http"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

const algodResponseHeaderTimeout = 30 * time.Second

// CreateAlgodClient creates an algod client from URL and optional token.
// Returns nil if the URL is empty.
func CreateAlgodClient(algodURL, algodToken string) (*algod.Client, error) {
	if algodURL == "" {
		return nil, nil
	}

	client, err := algod.MakeClientWithTransport(algodURL, algodToken, nil, algodHTTPTransport())
	if err != nil {
		return nil, fmt.Errorf("failed to create algod client: %w", err)
	}

	return client, nil
}

func algodHTTPTransport() http.RoundTripper {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	cloned := transport.Clone()
	cloned.ResponseHeaderTimeout = algodResponseHeaderTimeout
	return cloned
}
