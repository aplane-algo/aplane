// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	cosignermessage "github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

const (
	boundedRekeyLabel  = "__aplane_bounded1_rekey"
	boundedSpendLabel  = "__aplane_bounded1_spend"
	boundedLayer3Label = "__aplane_bounded1_layer3"
	boundedAcceptLabel = "__aplane_bounded1_accept"
	boundedPayLabel    = "__aplane_bounded1_effect_pay"
	boundedAxferLabel  = "__aplane_bounded1_effect_axfer"
	boundedOptInLabel  = "__aplane_bounded1_effect_asset_opt_in"

	boundedRekeyListCombineLabel = "__aplane_bounded1_rekey_list_combine"
	boundedRekeyListOrderedLabel = "__aplane_bounded1_rekey_list_ordered"
)

func (c *ComposedDSA) renderBoundedPrelude(publicKey []byte, params map[string]string, profile *BoundedAuthorizationProfile) (string, error) {
	metadata, err := c.boundedAuthorizationMetadataBase()
	if err != nil {
		return "", err
	}
	// The render-time guard for contradictions such as a cosigner beside a
	// spending-key rekey.
	if _, err := validatedBoundedProfile(profile, metadata); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("// === bounded transaction envelope ===\n")
	b.WriteString("txn Fee\n")
	b.WriteString(fmt.Sprintf("pushint %d\n", profile.MaxFee))
	b.WriteString("<=\nassert\n\n")

	b.WriteString("txn RekeyTo\nglobal ZeroAddress\n!=\n")
	b.WriteString("bnz " + boundedRekeyLabel + "\n\n")

	manifest := txeffects.BoundedManifest()
	for _, predicate := range manifest.Predicates {
		if predicate.Effect == txeffects.EffectRekey {
			continue
		}
		writeZeroAddressAssertion(&b, predicate.Field)
	}
	b.WriteString("\n")

	b.WriteString("txn TypeEnum\npushint 1\n==\nbnz " + boundedPayLabel + "\n")
	b.WriteString("txn TypeEnum\npushint 4\n==\nbnz " + boundedAxferLabel + "\n")
	b.WriteString("err\n\n")

	b.WriteString(boundedPayLabel + ":\n")
	writeSpendEffectDecision(&b, profileAllowsSpendEffect(profile, txeffects.SpendEffectPay))

	b.WriteString(boundedAxferLabel + ":\n")
	b.WriteString("txn AssetAmount\npushint 0\n==\n")
	b.WriteString("txn AssetReceiver\ntxn Sender\n==\n&&\n")
	b.WriteString("bnz " + boundedOptInLabel + "\n")
	writeSpendEffectDecision(&b, profileAllowsSpendEffect(profile, txeffects.SpendEffectAxfer))

	b.WriteString(boundedOptInLabel + ":\n")
	writeSpendEffectDecision(&b, profileAllowsSpendEffect(profile, txeffects.SpendEffectAssetOptIn))

	// No host rule gates a rekey: the rekey path ends here, before the spend
	// path's Layer 3 and cosigner checks.
	b.WriteString(boundedRekeyLabel + ":\n")
	writePureRekey := func() {
		b.WriteString("txn TypeEnum\npushint 1\n==\nassert\n")
		b.WriteString("txn Amount\npushint 0\n==\nassert\n")
		b.WriteString("txn Receiver\ntxn Sender\n==\nassert\n")
		b.WriteString("txn RekeyTo\nglobal ZeroAddress\n!=\nassert\n")
		for _, predicate := range manifest.Predicates {
			if predicate.Effect == txeffects.EffectRekey {
				continue
			}
			writeZeroAddressAssertion(&b, predicate.Field)
		}
	}
	switch {
	case profile.RekeyList != nil:
		// Only these addresses: a pure rekey to a listed target, nothing else.
		root, err := rekeyListRoot(params)
		if err != nil {
			return "", err
		}
		writePureRekey()
		renderListedRekey(&b, c.rekeyListProofIndex(metadata), root)
	case profile.Rekey == boundedmeta.RekeySpendingKey:
		writePureRekey()
		b.WriteString("b " + boundedAcceptLabel + "\n\n")
	default:
		b.WriteString("err\n\n")
	}

	b.WriteString(boundedSpendLabel + ":\n")
	if profile.Cosigner != nil {
		cosignerTEAL, err := c.renderCosignerAuthorization(publicKey, params, metadata)
		if err != nil {
			return "", err
		}
		b.WriteString(cosignerTEAL)
		b.WriteString("b " + boundedLayer3Label + "\n\n")
		b.WriteString(boundedLayer3Label + ":\n")
	}
	return b.String(), nil
}

func (c *ComposedDSA) renderCosignerAuthorization(publicKey []byte, params map[string]string, metadata *boundedmeta.Metadata) (string, error) {
	if metadata == nil || metadata.Cosigner == nil {
		return "", fmt.Errorf("bounded cosigner metadata is required")
	}
	cosignerPublicKey, err := c.validatedCosignerPublicKey(publicKey, params)
	if err != nil {
		return "", err
	}
	cosignerArgIndex := -1
	for _, slot := range metadata.ArgumentLayout {
		if slot.Source == boundedmeta.ArgSourceCosigner {
			cosignerArgIndex = slot.Index
			break
		}
	}
	if cosignerArgIndex < 0 {
		return "", fmt.Errorf("bounded cosigner argument slot is missing")
	}
	construction, ok := sigconstruction.ForWitnessKeyType(metadata.Cosigner.ComponentKeyType)
	if !ok {
		return "", fmt.Errorf("bounded cosigner key type %q has no signature construction", metadata.Cosigner.ComponentKeyType)
	}
	message := fmt.Sprintf("pushbytes 0x%s\npushbytes 0x%02x\nconcat\ntxn TxID\nconcat\nsha512_256",
		hex.EncodeToString([]byte(cosignermessage.DomainTagV1)), byte(cosignermessage.RoleCosigner))
	verify, err := construction.VerifyTEAL(cosignerPublicKey, message, cosignerArgIndex)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`// Cosigner-authorized pure spend
arg %d
len
pushint 0
>
assert
arg %d
len
pushint %d
<=
assert
%sassert
`, cosignerArgIndex, cosignerArgIndex, metadata.Cosigner.SignatureMaxSize, verify), nil
}

func writeSpendEffectDecision(b *strings.Builder, allowed bool) {
	if allowed {
		b.WriteString("b " + boundedSpendLabel + "\n\n")
		return
	}
	b.WriteString("err\n\n")
}

func writeZeroAddressAssertion(b *strings.Builder, field txeffects.TxField) {
	b.WriteString("txn " + string(field) + "\n")
	b.WriteString("global ZeroAddress\n==\nassert\n")
}

func renderBoundedAccept() string {
	return "\nb " + boundedAcceptLabel + "\n\n" + boundedAcceptLabel + ":\npushint 1\nreturn\n"
}

// rekeyListProofIndex is the list proof's argument slot.
func (c *ComposedDSA) rekeyListProofIndex(metadata *boundedmeta.Metadata) int {
	for _, slot := range metadata.ArgumentLayout {
		if slot.Source == boundedmeta.ArgSourceDerived && slot.Name == rekeyListProofSlot {
			return slot.Index
		}
	}
	return -1
}
