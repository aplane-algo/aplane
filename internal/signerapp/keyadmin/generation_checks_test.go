// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	nativefalconreg "github.com/aplane-algo/aplane/internal/signing/falcon1024/signerreg"
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

// cosignerHeldText is the warning for a cosigner key this signer holds as the
// key of selector, word for word.
func cosignerHeldText(selector string) string {
	return "The cosigner is a key this signer holds. It is the key of " + selector +
		", so the cosigner isn't independent of this signer: whoever controls this signer's keys can give both signatures."
}

// cosignedRequest is a bounded plain-host account gated by the given cosigner
// key, with a fee limit when one is named.
func cosignedRequest(cosignerPublicKeyHex, maxFee string) map[string]string {
	params := map[string]string{
		plainhost.ParameterSpendEffects:        "pay",
		plainhost.ParameterRecipientScope:      plainhost.RecipientScopeAny,
		plainhost.ParameterRekeyAuthority:      plainhost.RekeySpendingKey,
		boundedmeta.CosignerPublicKeyParameter: cosignerPublicKeyHex,
	}
	if maxFee != "" {
		params[plainhost.ParameterMaxFee] = maxFee
	}
	return params
}

// prepareThenGenerate prepares a request, generates what was reviewed, and
// generates the same request unreviewed, returning each one's warnings.
func prepareThenGenerate(t *testing.T, service Service, params map[string]string) (prepared, reviewed, unreviewed []string) {
	t.Helper()
	review, prepareErr := service.PrepareGenerateKey(plainHostKeyType, params)
	if prepareErr != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", prepareErr)
	}
	if projected := ProjectPrepareGenerateIPC(review, nil); !projected.Success || !slices.Equal(projected.Warnings, review.Warnings) {
		t.Fatalf("the IPC projection carries %q, the preparation %q", projected.Warnings, review.Warnings)
	}
	generated, err := service.GenerateReviewedKey(context.Background(), plainHostKeyType, review.Parameters,
		ReviewedValues{Fingerprint: review.ReviewFingerprint, BoundaryDigest: review.BoundaryDigest}, nil)
	if err != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	direct, err := service.GenerateKey(context.Background(), plainHostKeyType, params, nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %#v", err)
	}
	return review.Warnings, generated.Warnings, direct.Warnings
}

// A cosigner key that is also a key this signer holds is the user's choice. The
// account is prepared and generated, and each result says the cosigner is not
// independent of this signer, naming the key it is. An unrelated cosigner key
// says nothing.
func TestACosignerKeyThisSignerHoldsIsAllowedWithAWarning(t *testing.T) {
	ir, service, unrelated := setupPlainHost(t)
	held, heldHex := generateHeldFalconKey(t, ir, service)
	want := []string{cosignerHeldText(held)}

	for _, test := range []struct {
		name, cosigner string
	}{
		{"as stored", heldHex},
		{"upper case", strings.ToUpper(heldHex)},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, reviewed, unreviewed := prepareThenGenerate(t, service, cosignedRequest(test.cosigner, ""))
			for step, got := range map[string][]string{"prepare": prepared, "reviewed generation": reviewed, "unreviewed generation": unreviewed} {
				if !slices.Equal(got, want) {
					t.Errorf("%s Warnings = %q, want %q", step, got, want)
				}
			}
		})
	}

	// An account with a rekey-to list and no bounds takes a cosigner too, and is
	// told the same.
	t.Run("no bounds", func(t *testing.T) {
		params := map[string]string{
			plainhost.ParameterRekeyAuthority:      plainhost.RekeyPlusCosigned,
			plainhost.ParameterRekeyTo:             listedTarget.String(),
			boundedmeta.CosignerPublicKeyParameter: heldHex,
		}
		prepared, reviewed, unreviewed := prepareThenGenerate(t, service, params)
		for step, got := range map[string][]string{"prepare": prepared, "reviewed generation": reviewed, "unreviewed generation": unreviewed} {
			if !slices.Equal(got, want) {
				t.Errorf("%s Warnings = %q, want %q", step, got, want)
			}
		}
	})

	t.Run("unrelated cosigner", func(t *testing.T) {
		prepared, reviewed, unreviewed := prepareThenGenerate(t, service, cosignedRequest(hex.EncodeToString(unrelated), ""))
		for step, got := range map[string][]string{"prepare": prepared, "reviewed generation": reviewed, "unreviewed generation": unreviewed} {
			if len(got) != 0 {
				t.Errorf("%s Warnings = %q, want none", step, got)
			}
		}
	})

	t.Run("by reference name", func(t *testing.T) {
		params := cosignedRequest("", "")
		delete(params, boundedmeta.CosignerPublicKeyParameter)
		params[plainhost.ParameterCosigner] = prepareTestReference
		prepared, prepareErr := service.PrepareGenerateKey(plainHostKeyType, params)
		if prepareErr != nil || len(prepared.Warnings) != 0 {
			t.Fatalf("PrepareGenerateKey(reference) = %q, %#v; want no warning", warningsOfPrepared(prepared), prepareErr)
		}
	})

	// An account with no cosigner has nothing to warn of, whatever the signer holds.
	t.Run("no cosigner", func(t *testing.T) {
		params := cosignedRequest("", "")
		delete(params, boundedmeta.CosignerPublicKeyParameter)
		prepared, prepareErr := service.PrepareGenerateKey(plainHostKeyType, params)
		if prepareErr != nil || len(prepared.Warnings) != 0 {
			t.Fatalf("PrepareGenerateKey(no cosigner) = %q, %#v; want no warning", warningsOfPrepared(prepared), prepareErr)
		}
	})
}

// With a fee limit too low to pay alone as well, the account carries both
// warnings: the provider's first, then the signer's, every time.
func TestAHeldCosignerKeyAndALowFeeLimitBothWarn(t *testing.T) {
	ir, service, _ := setupPlainHost(t)
	held, heldHex := generateHeldFalconKey(t, ir, service)
	prepared, reviewed, unreviewed := prepareThenGenerate(t, service, cosignedRequest(heldHex, "0"))
	if len(prepared) != 2 || !strings.HasPrefix(prepared[0], "Fee limit 0 is too low to pay alone. ") || prepared[1] != cosignerHeldText(held) {
		t.Fatalf("prepare Warnings = %q, want the fee limit's and then the cosigner's", prepared)
	}
	for step, got := range map[string][]string{"reviewed generation": reviewed, "unreviewed generation": unreviewed} {
		if !slices.Equal(got, prepared) {
			t.Errorf("%s Warnings = %q, want %q", step, got, prepared)
		}
	}
	for range 5 {
		again, prepareErr := service.PrepareGenerateKey(plainHostKeyType, cosignedRequest(heldHex, "0"))
		if prepareErr != nil || !slices.Equal(again.Warnings, prepared) {
			t.Fatalf("a later preparation = %q, %#v; want %q", warningsOfPrepared(again), prepareErr, prepared)
		}
	}
}

// generateHeldFalconKey gives the signer a native Falcon account and returns
// its selector and public key. The compile mock gives every Falcon LogicSig
// account one address, so a native account is the held key that later
// generations in a test leave in place.
func generateHeldFalconKey(t *testing.T, ir *productruntime.Runtime, service Service) (selector, publicKeyHex string) {
	t.Helper()
	nativefalconreg.RegisterSigner()
	held, err := service.GenerateKey(context.Background(), "falcon1024", nil, nil)
	if err != nil {
		t.Fatalf("GenerateKey(falcon1024) error = %#v", err)
	}
	publicKeyHex = ir.KeyStore().GetPublicKeyHexMap()[held.Address]
	if len(publicKeyHex) != 2*boundedmeta.CosignerPublicKeySizeV1 {
		t.Fatalf("the held key's public key is %d hex characters", len(publicKeyHex))
	}
	return held.Address, publicKeyHex
}

func warningsOfPrepared(prepared *PreparedGeneration) []string {
	if prepared == nil {
		return nil
	}
	return prepared.Warnings
}

// rotatingTestKeyType is the rotating key type the tests hold: the WOTS+C
// triple, the quickest of the three to generate.
const rotatingTestKeyType = rotatingkey.RotatingTripleWotscV1

const rotatingTestGenesis = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="

// setupRotatingHolder is a signer that can generate plain hosts and a rotating
// account.
func setupRotatingHolder(t *testing.T) (*productruntime.Runtime, Service) {
	t.Helper()
	ir, service := setupGeneralProvider(t)
	service.NetworkGenesisHashes = func() map[string]string { return map[string]string{"testnet": rotatingTestGenesis} }
	if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{
		KeyType: rotatingTestKeyType, Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled,
	}); err != nil {
		t.Fatal(err)
	}
	return ir, service
}

func generateRotating(t *testing.T, service Service) *GenerateResult {
	t.Helper()
	rotating, err := service.GenerateKey(context.Background(), rotatingTestKeyType, map[string]string{rotatingkey.RotatingNetworkParameter: "testnet"}, nil)
	if err != nil {
		t.Fatalf("GenerateKey(%s) error = %#v", rotatingTestKeyType, err)
	}
	return rotating
}

// storedKeyFiles lists the files beside the given account's key file.
func storedKeyFiles(t *testing.T, ir *productruntime.Runtime, address string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(ir.KeyStore().GetCache()[address]))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// A rekey-to list that names a rotating account this signer holds is refused
// when the account is prepared and when it is generated, with the reason the
// signing gate gives for the rekey itself, and nothing is stored. A held account
// of another type, an address the signer doesn't hold, and both together are
// the user's choice.
func TestRekeyListRefusesARotatingAccountThisSignerHolds(t *testing.T) {
	ir, service := setupRotatingHolder(t)
	rotating := generateRotating(t, service)
	if got := ir.KeyStore().GetKeyTypes()[rotating.Address]; got != rotatingTestKeyType {
		t.Fatalf("the rotating account is stored as %q", got)
	}
	// A native account: the compile mock gives every Falcon LogicSig account one
	// address, and this one must stay held while those come and go.
	plain, err := service.GenerateKey(context.Background(), "ed25519", nil, nil)
	if err != nil {
		t.Fatalf("GenerateKey(ed25519) error = %#v", err)
	}
	unknown := listedTarget.String()
	request := func(rekey, targets string) map[string]string {
		params := generalParams(rekey)
		params[plainhost.ParameterRekeyTo] = targets
		return params
	}
	before := storedKeyFiles(t, ir, rotating.Address)
	keysBefore, listErr := service.ListKeys()
	if listErr != nil {
		t.Fatal(listErr)
	}

	// An address has one spelling, so no other form of it reaches the lookup.
	if _, prepareErr := service.PrepareGenerateKey(boundedHostKeyType, request(plainhost.RekeyOnlyThese, strings.ToLower(rotating.Address))); prepareErr == nil {
		t.Fatal("a lower-case address was taken as a rekey-to entry")
	}

	want := "rekey_to: " + rotatingkey.RekeyTargetRefusal(rotating.Address)
	if !strings.Contains(want, "cannot rekey to "+rotating.Address+": it is a rotating account") {
		t.Fatalf("refusal text = %q", want)
	}
	for _, test := range []struct {
		name    string
		params  map[string]string
		refused bool
	}{
		{"the rotating account alone", request(plainhost.RekeyOnlyThese, rotating.Address), true},
		{"the rotating account last", request(plainhost.RekeyOnlyThese, unknown+","+plain.Address+","+rotating.Address), true},
		{"the rotating account first", request(plainhost.RekeyOnlyThese, rotating.Address+","+unknown), true},
		{"with spaces around it", request(plainhost.RekeyOnlyThese, unknown+" , "+rotating.Address+" "), true},
		{"no bounds", map[string]string{plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese, plainhost.ParameterRekeyTo: rotating.Address}, true},
		{"a held account of another type", request(plainhost.RekeyOnlyThese, plain.Address), false},
		{"an address the signer doesn't hold", request(plainhost.RekeyOnlyThese, unknown), false},
		{"held and not held together", request(plainhost.RekeyOnlyThese, unknown+","+plain.Address), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, prepareErr := service.PrepareGenerateKey(boundedHostKeyType, test.params)
			if !test.refused {
				if prepareErr != nil {
					t.Fatalf("PrepareGenerateKey() error = %#v", prepareErr)
				}
				generated, generateErr := service.GenerateReviewedKey(context.Background(), boundedHostKeyType, prepared.Parameters,
					ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
				if generateErr != nil {
					t.Fatalf("GenerateReviewedKey() error = %#v", generateErr)
				}
				if _, deleteErr := service.DeleteKey(context.Background(), generated.Address); deleteErr != nil {
					t.Fatalf("DeleteKey() error = %#v", deleteErr)
				}
				return
			}
			if prepareErr == nil || prepareErr.Kind != ErrorInvalidInput || prepareErr.Message != want {
				t.Fatalf("PrepareGenerateKey() error = %#v, want %q", prepareErr, want)
			}
			if _, generateErr := service.GenerateKey(context.Background(), boundedHostKeyType, test.params, nil); generateErr == nil ||
				generateErr.Kind != ErrorInvalidInput || generateErr.Message != want {
				t.Fatalf("GenerateKey() error = %#v, want %q", generateErr, want)
			}
			// A review made before the signer held the account doesn't carry it past
			// generation: the reviewed call is checked like any other.
			if _, generateErr := service.GenerateReviewedKey(context.Background(), boundedHostKeyType, test.params,
				ReviewedValues{Fingerprint: "1:" + strings.Repeat("0", 64), BoundaryDigest: strings.Repeat("0", 64)}, nil); generateErr == nil ||
				generateErr.Kind != ErrorInvalidInput || generateErr.Message != want {
				t.Fatalf("GenerateReviewedKey() error = %#v, want %q", generateErr, want)
			}
			keysAfter, listErr := service.ListKeys()
			if listErr != nil {
				t.Fatal(listErr)
			}
			if after := storedKeyFiles(t, ir, rotating.Address); !slices.Equal(after, before) || len(keysAfter) != len(keysBefore) {
				t.Fatalf("a refused request changed the store: %v, was %v", after, before)
			}
		})
	}
}

// The refusal sees only what this signer holds, and only at generation. An
// account whose list named the address while the signer did not hold the
// rotating account there was admitted, and it still loads once the signer holds
// both: nothing rechecks a stored account. The same request made now is refused.
//
// A rotating account can't be imported from its mnemonic, so the test takes its
// key file out of the store and puts it back, as a restore would.
func TestAStoredRekeyListNamingAHeldRotatingAccountStillLoads(t *testing.T) {
	ir, service := setupRotatingHolder(t)
	rotating := generateRotating(t, service)
	keyFile := ir.KeyStore().GetCache()[rotating.Address]
	saved, readErr := os.ReadFile(keyFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeysForTest(ir, ir.KeyPaths()); err != nil {
		t.Fatal(err)
	}
	if _, held := ir.KeyStore().GetKeyTypes()[rotating.Address]; held {
		t.Fatal("the rotating account is still held")
	}

	params := generalParams(plainhost.RekeyOnlyThese)
	params[plainhost.ParameterRekeyTo] = rotating.Address
	// Not held: the address says nothing about its type, so it is taken.
	listed, err := service.GenerateKey(context.Background(), boundedHostKeyType, params, nil)
	if err != nil {
		t.Fatalf("GenerateKey(list naming a rotating account held elsewhere) error = %#v", err)
	}
	if err := os.WriteFile(keyFile, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeysForTest(ir, ir.KeyPaths()); err != nil {
		t.Fatalf("reload with both accounts: %v", err)
	}

	// The running signer reloaded, and a signer started on the same store reads
	// both accounts with no complaint.
	fresh := keystore.NewAtomicFileKeyStoreForPaths(ir.KeyPaths())
	if err := fresh.Unlock(testPassphrase); err != nil {
		t.Fatalf("Unlock(): %v", err)
	}
	if err := fresh.Scan(nil); err != nil {
		t.Fatalf("Scan(): %v", err)
	}
	for name, store := range map[string]*keystore.FileKeyStore{"reloaded": ir.KeyStore(), "restarted": fresh} {
		keyTypes := store.GetKeyTypes()
		if keyTypes[listed.Address] != boundedHostKeyType || keyTypes[rotating.Address] != rotatingTestKeyType {
			t.Fatalf("%s store holds %v", name, keyTypes)
		}
		if warnings := store.GetScanWarnings(); len(warnings) != 0 {
			t.Fatalf("%s store warns: %+v", name, warnings)
		}
		if got := store.GetSigningSummary()[listed.Address].Parameters[plainhost.ParameterRekeyTo]; got != rotating.Address {
			t.Fatalf("%s store: the account's list is %q", name, got)
		}
	}
	if details, detailsErr := service.GetKeyDetails(listed.Address); detailsErr != nil || details == nil {
		t.Fatalf("GetKeyDetails() = %+v, %#v", details, detailsErr)
	}

	want := "rekey_to: " + rotatingkey.RekeyTargetRefusal(rotating.Address)
	if _, prepareErr := service.PrepareGenerateKey(boundedHostKeyType, params); prepareErr == nil || prepareErr.Message != want {
		t.Fatalf("PrepareGenerateKey() error = %#v, want %q", prepareErr, want)
	}
}

// takeOutOfStore removes a held key's file and reloads, so the signer no longer
// holds the key, and returns a function that puts it back and reloads, as a
// restore would.
func takeOutOfStore(t *testing.T, ir *productruntime.Runtime, selector string) (putBack func()) {
	t.Helper()
	keyFile := ir.KeyStore().GetCache()[selector]
	saved, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeysForTest(ir, ir.KeyPaths()); err != nil {
		t.Fatal(err)
	}
	if _, held := ir.KeyStore().GetKeyTypes()[selector]; held {
		t.Fatalf("%s is still held", selector)
	}
	return func() {
		t.Helper()
		if err := os.WriteFile(keyFile, saved, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := reloadKeysForTest(ir, ir.KeyPaths()); err != nil {
			t.Fatal(err)
		}
		if _, held := ir.KeyStore().GetKeyTypes()[selector]; !held {
			t.Fatalf("%s is not held again", selector)
		}
	}
}

// The cosigner warning is about the keys the signer holds when it generates,
// not when it prepared the review. The reviewed values don't cover warnings, so
// a generation whose warnings differ from its review's still succeeds, and its
// result and the IPC projection of it carry the warnings of the account made.
// The provider's fee-limit warning depends on the request alone and is in both.
func TestGenerationWarningsAreThoseOfTheKeysHeldAtGeneration(t *testing.T) {
	for _, test := range []struct {
		name, maxFee string
		feeWarning   bool
	}{
		{"cosigner warning alone", "", false},
		{"after a fee-limit warning", "0", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ir, service, _ := setupPlainHost(t)
			held, heldHex := generateHeldFalconKey(t, ir, service)
			params := cosignedRequest(heldHex, test.maxFee)
			var fee []string
			if test.feeWarning {
				quiet, prepareErr := service.PrepareGenerateKey(plainHostKeyType, cosignedRequest(heldHex, test.maxFee))
				if prepareErr != nil || len(quiet.Warnings) != 2 || !strings.HasPrefix(quiet.Warnings[0], "Fee limit 0 is too low to pay alone. ") {
					t.Fatalf("PrepareGenerateKey() = %q, %#v", warningsOfPrepared(quiet), prepareErr)
				}
				fee = quiet.Warnings[:1]
			}
			withCosigner := append(slices.Clone(fee), cosignerHeldText(held))
			generate := func(review *PreparedGeneration) []string {
				t.Helper()
				generated, err := service.GenerateReviewedKey(context.Background(), plainHostKeyType, review.Parameters,
					ReviewedValues{Fingerprint: review.ReviewFingerprint, BoundaryDigest: review.BoundaryDigest}, nil)
				if err != nil {
					t.Fatalf("GenerateReviewedKey() error = %#v", err)
				}
				projected := ProjectGenerateIPC(generated, nil)
				if !projected.Success || projected.Address != generated.Address || !slices.Equal(projected.Warnings, generated.Warnings) {
					t.Fatalf("the IPC projection carries %q, the generation %q", projected.Warnings, generated.Warnings)
				}
				if _, deleteErr := service.DeleteKey(context.Background(), generated.Address); deleteErr != nil {
					t.Fatalf("DeleteKey() error = %#v", deleteErr)
				}
				return generated.Warnings
			}

			// Reviewed while the signer did not hold the key, generated once it does:
			// the warning is new since the review.
			putBack := takeOutOfStore(t, ir, held)
			review, prepareErr := service.PrepareGenerateKey(plainHostKeyType, params)
			if prepareErr != nil || !slices.Equal(review.Warnings, fee) {
				t.Fatalf("PrepareGenerateKey(key not held) = %q, %#v; want %q", warningsOfPrepared(review), prepareErr, fee)
			}
			putBack()
			if got := generate(review); !slices.Equal(got, withCosigner) {
				t.Fatalf("generation once the key is held: Warnings = %q, want %q", got, withCosigner)
			}

			// Reviewed while the signer held the key, generated once it doesn't: the
			// review's warning no longer applies.
			review, prepareErr = service.PrepareGenerateKey(plainHostKeyType, params)
			if prepareErr != nil || !slices.Equal(review.Warnings, withCosigner) {
				t.Fatalf("PrepareGenerateKey(key held) = %q, %#v; want %q", warningsOfPrepared(review), prepareErr, withCosigner)
			}
			takeOutOfStore(t, ir, held)
			if got := generate(review); !slices.Equal(got, fee) {
				t.Fatalf("generation once the key is gone: Warnings = %q, want %q", got, fee)
			}
		})
	}
}

// A review made while the signer did not hold the rotating account does not
// carry the request past generation once it does: the refusal reads the keys
// held when the account would be written.
func TestAReviewMadeBeforeTheRotatingAccountWasHeldIsRefusedAtGeneration(t *testing.T) {
	ir, service := setupRotatingHolder(t)
	rotating := generateRotating(t, service)
	params := generalParams(plainhost.RekeyOnlyThese)
	params[plainhost.ParameterRekeyTo] = rotating.Address

	putBack := takeOutOfStore(t, ir, rotating.Address)
	review, prepareErr := service.PrepareGenerateKey(boundedHostKeyType, params)
	if prepareErr != nil {
		t.Fatalf("PrepareGenerateKey(rotating account not held) error = %#v", prepareErr)
	}
	putBack()
	want := "rekey_to: " + rotatingkey.RekeyTargetRefusal(rotating.Address)
	generated, err := service.GenerateReviewedKey(context.Background(), boundedHostKeyType, review.Parameters,
		ReviewedValues{Fingerprint: review.ReviewFingerprint, BoundaryDigest: review.BoundaryDigest}, nil)
	if err == nil || err.Kind != ErrorInvalidInput || err.Message != want {
		t.Fatalf("GenerateReviewedKey() = %+v, %#v; want %q", generated, err, want)
	}
}

// The checks against the held keys run under the mutation lock, after the
// checks that need no key list. So a request that fails one of those is told
// that, not that its rekey-to list names a rotating account: a locked signer
// and a generation requirement each come first. The same request with neither
// in the way gets the rotating refusal.
func TestHeldKeyChecksComeAfterTheLockAndTheGenerationChecks(t *testing.T) {
	ir, service := setupRotatingHolder(t)
	rotating := generateRotating(t, service)
	params := func() map[string]string {
		request := generalParams(plainhost.RekeyOnlyThese)
		request[plainhost.ParameterRekeyTo] = rotating.Address
		return request
	}
	rotatingRefusal := "rekey_to: " + rotatingkey.RekeyTargetRefusal(rotating.Address)
	bogus := ReviewedValues{Fingerprint: "1:" + strings.Repeat("0", 64), BoundaryDigest: strings.Repeat("0", 64)}
	attempt := func() map[string]*Error {
		_, prepareErr := service.PrepareGenerateKey(boundedHostKeyType, params())
		_, generateErr := service.GenerateKey(context.Background(), boundedHostKeyType, params(), nil)
		_, reviewedErr := service.GenerateReviewedKey(context.Background(), boundedHostKeyType, params(), bogus, nil)
		return map[string]*Error{"PrepareGenerateKey": prepareErr, "GenerateKey": generateErr, "GenerateReviewedKey": reviewedErr}
	}
	expect := func(t *testing.T, kind ErrorKind, contains string) {
		t.Helper()
		for call, err := range attempt() {
			if err == nil || err.Kind != kind || !strings.Contains(err.Message, contains) {
				t.Errorf("%s() error = %#v, want kind %v containing %q", call, err, kind, contains)
			}
			if err != nil && contains != rotatingRefusal && strings.Contains(err.Message, "rotating account") {
				t.Errorf("%s() reports the rotating target first: %q", call, err.Message)
			}
		}
	}

	t.Run("nothing in the way", func(t *testing.T) { expect(t, ErrorInvalidInput, rotatingRefusal) })

	t.Run("a generation requirement", func(t *testing.T) {
		ir.Config().SetGenerationRequirements(false, true)
		t.Cleanup(func() { ir.Config().SetGenerationRequirements(false, false) })
		expect(t, ErrorInvalidInput, "require_cosigner")
	})

	// Last: nothing unlocks the signer again.
	t.Run("a locked signer", func(t *testing.T) {
		ir.Lock()
		// The key list still names the account, so the order is what decides.
		if got := ir.KeyStore().GetKeyTypes()[rotating.Address]; got != rotatingTestKeyType {
			t.Fatalf("a locked signer's key list has %q for the rotating account", got)
		}
		expect(t, ErrorLocked, "signer is not unlocked")
	})
}
