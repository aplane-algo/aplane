// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/cosigner/verify"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/falconparams"
	"github.com/aplane-algo/aplane/internal/keys"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// An admin-key bounded rekey may only move the account to a signing
// credential this signer holds. The rule is a signer invariant, not a policy
// setting: reject_foreign_rekey can be switched off, this cannot. It exists
// so that a contract-admin ceremony never hands an account to an unknown or
// unusable authority (a typo, an address the operator merely recognises, a
// witness or rotating credential that cannot authorize ordinary
// transactions). Leaving APlane custody is deliberately two steps: an admin
// rekey to a local credential, then an ordinary rekey from that credential
// under the signer's normal policy.
//
// The target is checked twice. Before policy and approval, from the planner
// snapshot, so an ineligible target is refused without decrypting anything
// or involving the operator. Again at release, after approval, by loading
// the credential from the key session and proving it can sign: a credential
// deleted or replaced between approval and release fails the second check.
//
// Neither TEAL nor the offline aprekey helper can inspect this signer's
// inventory, so the rule is enforced here and only here; the admin signature
// still binds the exact target the helper presents for review.

// adminRekeyTargetChallengeDomain separates the self-test message from every
// transaction and component domain: no signature made here can be replayed
// as authorization for anything.
const adminRekeyTargetChallengeDomain = "APLANE_BOUNDED_ADMIN_TARGET_SELFTEST_V1"

// adminRekeyTargetIneligible reports why a held credential cannot receive an
// admin-key bounded rekey, or "" when it can. Only nonrotating account
// credentials whose complete authorization path is one local signature
// qualify: native Ed25519, native Falcon-1024, and plain DSA LogicSigs. A
// bounded or guarded LogicSig needs more than its spending key, a generic
// LogicSig has no signing credential, a witness is not an account, and a
// rotating account's address is a one-time stage.
func adminRekeyTargetIneligible(category, keyType string, bounded bool) string {
	switch category {
	case keys.CategoryEd25519, keys.CategoryNativePQ:
		return ""
	case keys.CategoryDSALsig:
		if bounded {
			return "a bounded account"
		}
		if keytypes.IsGuardedAccountKeyType(keyType) {
			return "a guarded account"
		}
		return ""
	case keys.CategoryGenericLsig:
		return "a generic LogicSig with no signing credential"
	case keys.CategoryWitness:
		return "a witness credential, not an account"
	case keys.CategoryRotatingLsig:
		return "a rotating account"
	}
	return fmt.Sprintf("an unsupported credential category %q", category)
}

// checkBoundedAdminRekeyTarget is the pre-policy check: the rekey target of
// an admin-key bounded rekey must be a held, eligible credential. A rekey to
// the sender itself returns the account to its own program and names no
// other credential, so it passes.
func (s *Service) checkBoundedAdminRekeyTarget(txn types.Transaction) *ServiceError {
	if txn.RekeyTo == txn.Sender {
		return nil
	}
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return internal("planner not configured")
	}
	snapshot := s.Planner.Snapshot()
	target := txn.RekeyTo.String()
	keyType, held := snapshot.KeyTypes[target]
	if !held {
		return boundedAdminTargetRejected(fmt.Sprintf("rekey target %s is not a key held by this signer; an admin rekey may only move the account to a signing credential this signer holds", target))
	}
	meta := snapshot.KeyMetadata[target]
	if why := adminRekeyTargetIneligible(meta.Category, keyType, meta.BoundedAuthorization != nil); why != "" {
		return boundedAdminTargetRejected(fmt.Sprintf("rekey target %s is %s and cannot receive an admin rekey", target, why))
	}
	return nil
}

// adminTargetKeyGetter is the slice of the key session the release-time
// check needs.
type adminTargetKeyGetter interface {
	GetKeyWithContext(ctx context.Context, address string) (*coresigning.KeyMaterial, error)
}

// verifyBoundedAdminRekeyTarget is the release-time check, run after
// approval: the target credential is loaded from the session, classified
// again from its own material, and proven able to sign. The session lookup
// is by address, and the key file's address binding is validated at scan,
// so a successful load already ties the credential to the target; the
// self-test adds that the private material works and, where the address is
// a function of the public key alone, that the two still agree.
func verifyBoundedAdminRekeyTarget(ctx context.Context, session adminTargetKeyGetter, txn types.Transaction) *ServiceError {
	if txn.RekeyTo == txn.Sender {
		return nil
	}
	if session == nil {
		return internal("key session unavailable for bounded-admin target verification")
	}
	target := txn.RekeyTo.String()
	km, err := session.GetKeyWithContext(ctx, target)
	if err != nil || km == nil {
		return boundedAdminTargetRejected(fmt.Sprintf("rekey target %s is no longer a key held by this signer", target))
	}
	defer zeroLoadedKeyMaterial(km)
	if why := adminRekeyTargetIneligible(km.Category, km.Type, km.BoundedAuthorization != nil); why != "" {
		return boundedAdminTargetRejected(fmt.Sprintf("rekey target %s is %s and cannot receive an admin rekey", target, why))
	}
	if err := selfTestAdminRekeyTarget(km, txn.RekeyTo); err != nil {
		return boundedAdminTargetRejected(fmt.Sprintf("rekey target %s failed its signing self-test: %v", target, err))
	}
	return nil
}

// selfTestAdminRekeyTarget signs a fresh domain-separated challenge with the
// credential and verifies the signature against its stored public key. The
// signature is zeroed before return and is never released.
func selfTestAdminRekeyTarget(km *coresigning.KeyMaterial, target types.Address) error {
	provider := coresigning.GetProviderForKey(km.Type, km.BaseKeyType)
	if provider == nil {
		return fmt.Errorf("no signing provider for key type %s", km.Type)
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("read challenge randomness: %w", err)
	}
	message := append([]byte(adminRekeyTargetChallengeDomain), challenge...)
	signature, err := provider.SignMessage(km, message)
	if err != nil {
		return fmt.Errorf("sign challenge: %w", err)
	}
	defer securecrypto.ZeroBytes(signature)

	switch km.Category {
	case keys.CategoryEd25519:
		if len(km.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("stored Ed25519 public key has length %d", len(km.PublicKey))
		}
		if !bytes.Equal(km.PublicKey, target[:]) {
			return fmt.Errorf("stored public key does not derive the target address")
		}
		if !ed25519.Verify(ed25519.PublicKey(km.PublicKey), message, signature) {
			return fmt.Errorf("Ed25519 signature did not verify")
		}
	case keys.CategoryNativePQ:
		if km.PQAddressSalt == nil {
			return fmt.Errorf("native Falcon key has no address salt")
		}
		derived, err := nativefalcon.Address(*km.PQAddressSalt, km.PublicKey)
		if err != nil {
			return fmt.Errorf("derive native Falcon address: %w", err)
		}
		if derived != target {
			return fmt.Errorf("stored public key does not derive the target address")
		}
		if err := verify.VerifyFalcon1024(km.PublicKey, message, signature); err != nil {
			return err
		}
	case keys.CategoryDSALsig:
		// A plain DSA LogicSig signs with its base primitive, and the stored
		// public key's size says which one: the two sizes are frozen and
		// distinct, so no registry lookup is needed to pick the verifier.
		switch len(km.PublicKey) {
		case falconparams.PublicKeySize:
			if err := verify.VerifyFalcon1024(km.PublicKey, message, signature); err != nil {
				return err
			}
		case ed25519.PublicKeySize:
			if !ed25519.Verify(ed25519.PublicKey(km.PublicKey), message, signature) {
				return fmt.Errorf("Ed25519 LogicSig signature did not verify")
			}
		default:
			return fmt.Errorf("stored DSA public key has unsupported length %d", len(km.PublicKey))
		}
	default:
		return fmt.Errorf("credential category %q cannot be self-tested", km.Category)
	}
	return nil
}
