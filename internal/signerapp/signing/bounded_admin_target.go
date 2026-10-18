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
	"github.com/aplane-algo/aplane/internal/lsigprovider"
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

// The only LogicSig families eligible as admin rekey targets. Both programs
// are pure signature gates: they verify one signature over the transaction
// and impose no spending, fee, close-out or rekey restriction of their own.
// Every other DSA LogicSig (bounded, guarded, or an author-composed template
// whose TEAL suffix the signer cannot inspect) may restrict what the account
// can do once it is the authority, up to forbidding the rekey that would
// undo the move, so eligibility is an explicit allowlist rather than a
// category minus known exclusions.
const (
	plainFalcon1024LsigKeyType = "aplane.falcon1024.v1"
	plainEd25519LsigKeyType    = "aplane.ed25519.v1"
)

// adminRekeyTargetIneligible reports why a held credential cannot receive an
// admin-key bounded rekey, or "" when it can. Only nonrotating account
// credentials whose complete authorization path is one unrestricted local
// signature qualify: native Ed25519, native Falcon-1024, and the two plain
// DSA LogicSig families. A bounded or guarded LogicSig needs more than its
// spending key, a composed template may restrict spending, a generic
// LogicSig has no signing credential, a witness is not an account, and a
// rotating account's address is a one-time stage.
func adminRekeyTargetIneligible(category, keyType string, bounded bool) string {
	switch category {
	case keys.CategoryEd25519, keys.CategoryNativePQ:
		return ""
	case keys.CategoryDSALsig:
		switch {
		case bounded:
			return "a bounded account"
		case keytypes.IsGuardedAccountKeyType(keyType):
			return "a guarded account"
		case keyType == plainFalcon1024LsigKeyType, keyType == plainEd25519LsigKeyType:
			return ""
		}
		return fmt.Sprintf("a %s LogicSig, not one of the plain %s or %s families", keyType, plainFalcon1024LsigKeyType, plainEd25519LsigKeyType)
	case keys.CategoryGenericLsig:
		return "a generic LogicSig with no signing credential"
	case keys.CategoryWitness:
		return "a witness credential, not an account"
	case keys.CategoryRotatingLsig:
		return "a rotating account"
	}
	return fmt.Sprintf("an unsupported credential category %q", category)
}

// adminRekeyReturnsToOwnProgram reports whether the transaction is a rekey of
// the bounded account to itself: the sender is the bounded program that
// authorizes the request and the target is that same address. That names no
// other credential and leaves the account on a program this signer holds, so
// it is the one self-rekey that needs no destination check. A rekey-to-self
// from any other sender is a different matter: the bounded program is then
// the standing authority for some other account, and clearing that
// authority hands the account back to its own key, which must be checked
// like any other destination.
func adminRekeyReturnsToOwnProgram(txn types.Transaction, boundedAccount string) bool {
	return txn.RekeyTo == txn.Sender && txn.Sender.String() == boundedAccount
}

// checkBoundedAdminRekeyTarget is the pre-policy check: the rekey target of
// an admin-key bounded rekey must be a held, eligible credential.
// boundedAccount is the address of the bounded program authorizing the
// request (the sign request's auth address).
func (s *Service) checkBoundedAdminRekeyTarget(txn types.Transaction, boundedAccount string) *ServiceError {
	if adminRekeyReturnsToOwnProgram(txn, boundedAccount) {
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
// self-test adds that the private material works and that the stored
// public key or program still derives the target address.
func verifyBoundedAdminRekeyTarget(ctx context.Context, session adminTargetKeyGetter, txn types.Transaction, boundedAccount string) *ServiceError {
	if adminRekeyReturnsToOwnProgram(txn, boundedAccount) {
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
	if km.Category == keys.CategoryDSALsig {
		if err := verifyPlainLogicSigConstruction(ctx, km, txn.RekeyTo); err != nil {
			return boundedAdminTargetRejected(fmt.Sprintf("rekey target %s failed its program check: %v", target, err))
		}
	}
	if err := selfTestAdminRekeyTarget(km, txn.RekeyTo); err != nil {
		return boundedAdminTargetRejected(fmt.Sprintf("rekey target %s failed its signing self-test: %v", target, err))
	}
	return nil
}

// verifyPlainLogicSigConstruction proves that a plain LogicSig credential's
// stored program is the canonical compilation of its family for its stored
// public key, and that this program derives the target address. The family
// provider re-derives the program exactly as key generation did (the TEAL
// compiler owns the layout and the off-curve salt, so nothing is
// reconstructed by hand) and the bytes must match. Without this, a program
// that hashes to the target and a key that signs correctly could still be
// unrelated, and the account would move to a program that rejects the key.
// This is the one step of the target rule that needs the signer's configured
// compiler; native targets never reach it.
func verifyPlainLogicSigConstruction(ctx context.Context, km *coresigning.KeyMaterial, target types.Address) error {
	if len(km.Bytecode) == 0 {
		return fmt.Errorf("stored LogicSig credential has no program")
	}
	provider, ok := lsigprovider.Get(km.Type).(lsigprovider.SigningProvider)
	if !ok {
		return fmt.Errorf("no LogicSig provider registered for %s", km.Type)
	}
	bytecode, address, err := provider.DeriveLsig(ctx, km.PublicKey, km.Parameters)
	if err != nil {
		return fmt.Errorf("derive the canonical %s program: %w", km.Type, err)
	}
	if !bytes.Equal(bytecode, km.Bytecode) {
		return fmt.Errorf("stored program is not the canonical %s program for the stored public key", km.Type)
	}
	if address != target.String() {
		return fmt.Errorf("canonical program does not derive the target address")
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
		// verifyPlainLogicSigConstruction already tied the program to the
		// public key and the target. A plain DSA LogicSig signs with its base
		// primitive, and the stored public key's size says which one: the two
		// sizes are frozen and distinct, so no registry lookup is needed.
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
