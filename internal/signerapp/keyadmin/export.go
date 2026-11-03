// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"errors"
	"fmt"

	algomnemonic "github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/signerapp/svcerr"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// ExportOutcomeReleased is the audit outcome of an export whose phrase was
// handed to the transport.
const ExportOutcomeReleased = "released"

var errExportNotEligible = errors.New("mnemonic export not eligible")

// ExportKey releases only native recovery material, after fresh authentication.
// A successful phrase leaves the service only through deliver; the returned
// result never carries it. A failed result was not delivered, and the caller
// reports it.
func (s Service) ExportKey(ctx context.Context, req adminproto.ExportKeyRequest, deliver adminproto.ExportDelivery) (result adminproto.ExportKeyResult) {
	defer crypto.ZeroBytes(req.Passphrase)
	result.Address = req.Address
	defer func() {
		crypto.ZeroBytes(result.Mnemonic)
		result.Mnemonic = nil
		if s.AuditLog != nil {
			outcome := result.Code
			if result.Success {
				outcome = ExportOutcomeReleased
			}
			s.AuditLog.LogKeyExported(ctx, req.Address, result.KeyType, outcome)
		}
	}()
	fail := func(kind svcerr.Kind, message string) adminproto.ExportKeyResult {
		crypto.ZeroBytes(result.Mnemonic)
		result.Mnemonic = nil
		result.Success = false
		result.Code, result.Error = string(kind), message
		return result
	}
	if s.Runtime == nil || deliver == nil {
		return fail(svcerr.KindInternal, "export is not wired to a runtime and transport")
	}
	if !s.Runtime.IsUnlocked() {
		return fail(svcerr.KindLocked, "signer is not unlocked")
	}
	// Verify before taking the mutation lock so the Argon2id cost does not
	// stall other key administration; the lock below re-checks the state.
	if len(req.Passphrase) == 0 || crypto.VerifyPassphraseWithStoreRoot(req.Passphrase, s.Runtime.KeyPaths().KeystoreMetadataDir()) != nil {
		return fail(svcerr.KindInvalidPassphrase, "incorrect passphrase")
	}
	unlock, lockErr := s.lockUnlockedMutation()
	if lockErr != nil {
		return fail(lockErr.Kind, lockErr.Message)
	}
	defer unlock()
	useCtx, release := s.Runtime.KeyUseContext(ctx)
	defer release()
	if useCtx.Err() != nil {
		return fail(svcerr.KindLocked, "signer is locked or request canceled")
	}
	keyFile, err := s.Runtime.FindKeyFile(req.Address)
	if err != nil {
		return fail(svcerr.KindNotFound, "key not found")
	}
	err = s.Runtime.WithKeyring(func(kr *crypto.Keyring) error {
		data, err := keys.ReadDecryptedKeyJSONWithKeyring(keyFile, kr)
		if err != nil {
			return err
		}
		defer crypto.ZeroBytes(data)
		// The full parse re-derives native Falcon keys from their entropy, so a
		// released phrase is proven to recover this exact account.
		payload, err := keys.ParsePayload(data)
		if err != nil {
			return err
		}
		defer payload.ZeroSecrets()
		selector, err := payload.Selector()
		if err != nil {
			return err
		}
		if selector != req.Address {
			return fmt.Errorf("credential selector mismatch")
		}
		result.KeyType = payload.KeyType
		words, wordCount, err := recoveryPhrase(payload)
		if err != nil {
			return err
		}
		result.Mnemonic = []byte(words)
		result.WordCount = wordCount
		return nil
	})
	switch {
	case errors.Is(err, errExportNotEligible):
		if result.KeyType == nativefalcon.KeyType {
			return fail(svcerr.KindUnavailable, "mnemonic unavailable: this Falcon credential has no recovery entropy; use encrypted backup")
		}
		return fail(svcerr.KindForbidden, "mnemonic export is available only for native ed25519 and falcon1024 keys")
	case err != nil:
		return fail(svcerr.KindInternal, "failed to read native recovery material")
	}
	if useCtx.Err() != nil {
		return fail(svcerr.KindLocked, "signer is locked or request canceled")
	}
	result.Success = true
	if err := deliver(result); err != nil {
		return fail(svcerr.KindInternal, "recovery phrase delivery failed")
	}
	return result
}

// recoveryPhrase encodes an eligible payload's recovery phrase. Eligibility is
// keys.Payload.RecoveryPhraseAvailable, the same rule key details project.
func recoveryPhrase(payload *keys.Payload) (string, int, error) {
	if !payload.RecoveryPhraseAvailable() {
		return "", 0, errExportNotEligible
	}
	handler, err := mnemonic.GetHandler(payload.KeyType)
	if err != nil {
		return "", 0, err
	}
	var words string
	if payload.Category == keys.CategoryNativePQ {
		words, err = handler.EntropyToMnemonic(payload.RecoveryEntropy)
	} else {
		// Ed25519 phrases encode the private key seed, not separate entropy.
		words, err = algomnemonic.FromPrivateKey(payload.PrivateKey)
	}
	if err != nil {
		return "", 0, err
	}
	return words, handler.WordCount(), nil
}

func (s IPCService) ExportKey(ctx context.Context, req adminproto.ExportKeyRequest, deliver adminproto.ExportDelivery) adminproto.ExportKeyResult {
	return s.Service.ExportKey(ctx, req, deliver)
}
