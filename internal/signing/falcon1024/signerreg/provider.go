// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"fmt"
	"sync"

	"github.com/algorand/falcon"
	"github.com/algorand/go-algorand-sdk/v2/types"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/internal/signing/falcon1024/signerops"
)

type Provider struct{}

var _ signing.TransactionAuthorizer = (*Provider)(nil)

func (*Provider) RoutingFamily() string { return nativefalcon.KeyType }

func (p *Provider) LoadKeyMaterial(key signing.ProviderKey) (*signing.KeyMaterial, error) {
	if key.Type != nativefalcon.KeyType {
		return nil, fmt.Errorf("native Falcon provider cannot load key type %q", key.Type)
	}
	if len(key.PrivateKey) != falcon.PrivateKeySize {
		return nil, fmt.Errorf("native Falcon private key length %d, want %d", len(key.PrivateKey), falcon.PrivateKeySize)
	}
	privateKey := new(falcon.PrivateKey)
	copy(privateKey[:], key.PrivateKey)
	return &signing.KeyMaterial{Type: nativefalcon.KeyType, Value: privateKey}, nil
}

func (p *Provider) SignMessage(key *signing.KeyMaterial, message []byte) ([]byte, error) {
	if err := signing.ValidateKeyMaterial(key, nativefalcon.KeyType); err != nil {
		return nil, err
	}
	privateKey, ok := key.Value.(*falcon.PrivateKey)
	if !ok || privateKey == nil {
		return nil, fmt.Errorf("invalid native Falcon private key material")
	}
	signature, err := privateKey.SignCompressed(message)
	if err != nil {
		return nil, fmt.Errorf("sign with native Falcon key: %w", err)
	}
	return signature, nil
}

func (p *Provider) AuthorizeTransaction(key *signing.KeyMaterial, txn types.Transaction, authorizer types.Address) (types.SignedTxn, error) {
	if err := signing.ValidateKeyMaterial(key, nativefalcon.KeyType); err != nil {
		return types.SignedTxn{}, err
	}
	privateKey, ok := key.Value.(*falcon.PrivateKey)
	if !ok || privateKey == nil {
		return types.SignedTxn{}, fmt.Errorf("invalid native Falcon private key material")
	}
	if key.Category != "native_pq" {
		return types.SignedTxn{}, fmt.Errorf("native Falcon key category is %q, want native_pq", key.Category)
	}
	if key.PQScheme != nativefalcon.Scheme {
		return types.SignedTxn{}, fmt.Errorf("native Falcon PQ scheme is %q, want %q", key.PQScheme, nativefalcon.Scheme)
	}
	if key.PQAddressSalt == nil {
		return types.SignedTxn{}, fmt.Errorf("native Falcon key is missing PQ address salt")
	}
	return signerops.AuthorizeTransaction(privateKey, key.PublicKey, *key.PQAddressSalt, txn, authorizer)
}

func (*Provider) ZeroKey(key *signing.KeyMaterial) {
	if key == nil {
		return
	}
	if privateKey, ok := key.Value.(*falcon.PrivateKey); ok && privateKey != nil {
		securecrypto.ZeroBytes(privateKey[:])
	}
	key.Type = ""
	key.Value = nil
}

var registerProviderOnce sync.Once

func RegisterProvider() {
	registerProviderOnce.Do(func() { signing.Register(&Provider{}) })
}
