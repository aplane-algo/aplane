// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa

import (
	"encoding/hex"
	"fmt"
	"strings"

	boundedmessage "github.com/aplane-algo/aplane/internal/boundedadmin/message"
	"github.com/aplane-algo/aplane/internal/txeffects"
)

const (
	boundedRekeyLabel  = "__aplane_bounded1_rekey"
	boundedSpendLabel  = "__aplane_bounded1_spend"
	boundedAcceptLabel = "__aplane_bounded1_accept"
	boundedPayLabel    = "__aplane_bounded1_effect_pay"
	boundedAxferLabel  = "__aplane_bounded1_effect_axfer"
	boundedOptInLabel  = "__aplane_bounded1_effect_asset_opt_in"
)

func (c *ComposedDSA) renderBoundedPrelude(publicKey []byte, params map[string]string, profile *BoundedAuthorizationProfile) (string, error) {
	metadata, err := c.boundedAuthorizationMetadataBase()
	if err != nil {
		return "", err
	}
	profileEncoding, err := CanonicalBoundedProfile(profile, metadata)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("// === bounded1 transaction envelope ===\n")
	b.WriteString("txn Fee\n")
	b.WriteString(fmt.Sprintf("pushint %d\n", profile.MaxFee))
	b.WriteString("<=\nassert\n\n")

	b.WriteString("txn RekeyTo\nglobal ZeroAddress\n!=\n")
	b.WriteString("bnz " + boundedRekeyLabel + "\n\n")

	manifest := txeffects.Bounded1Manifest()
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

	b.WriteString(boundedRekeyLabel + ":\n")
	operation, enabled := findAdminOperation(profile, AdminOperationRekey)
	if !enabled {
		b.WriteString("err\n\n")
	} else {
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
		if operation.Authorization == AdminAuthorizationAdminKey {
			adminTEAL, err := c.renderAdminKeyAuthorization(publicKey, params, profileEncoding, metadata.ArgumentLayout[len(metadata.ArgumentLayout)-1].Index)
			if err != nil {
				return "", err
			}
			b.WriteString(adminTEAL)
		}
		if operation.PolicyGate == AdminPolicyGateLayer3 {
			b.WriteString("b " + boundedSpendLabel + "\n\n")
		} else {
			b.WriteString("b " + boundedAcceptLabel + "\n\n")
		}
	}

	b.WriteString(boundedSpendLabel + ":\n")
	return b.String(), nil
}

func writeSpendEffectDecision(b *strings.Builder, allowed bool) {
	if allowed {
		b.WriteString("b " + boundedSpendLabel + "\n\n")
		return
	}
	b.WriteString("err\n\n")
}

func (c *ComposedDSA) renderAdminKeyAuthorization(publicKey []byte, params map[string]string, profileEncoding []byte, adminArgIndex int) (string, error) {
	adminPublicKey, err := c.validatedAdminPublicKey(publicKey, params)
	if err != nil {
		return "", err
	}
	behaviorEncoding, err := canonicalBehaviorParameters(params, c.params)
	if err != nil {
		return "", err
	}
	binding := boundedProgramBinding(c.keyType, c.baseKeyType, c.ops.TEALVersion(), publicKey, adminPublicKey, profileEncoding, behaviorEncoding)
	prefix, err := boundedmessage.Prefix(boundedmessage.OperationRekey, binding[:])
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`// Contract-admin-authorized pure rekey
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
pushbytes 0x%s
txn TxID
concat
sha512_256
arg %d
pushbytes 0x%s
falcon_verify
assert
`, adminArgIndex, adminArgIndex, BoundedAdminSignatureMaxSize,
		hex.EncodeToString(prefix), adminArgIndex, hex.EncodeToString(adminPublicKey)), nil
}

func writeZeroAddressAssertion(b *strings.Builder, field txeffects.TxField) {
	b.WriteString("txn " + string(field) + "\n")
	b.WriteString("global ZeroAddress\n==\nassert\n")
}

func findAdminOperation(profile *BoundedAuthorizationProfile, kind AdminOperationKind) (AdminOperationSpec, bool) {
	for _, operation := range profile.AdminOperations {
		if operation.Kind == kind {
			return operation, true
		}
	}
	return AdminOperationSpec{}, false
}

func renderBoundedAccept() string {
	return "\nb " + boundedAcceptLabel + "\n\n" + boundedAcceptLabel + ":\npushint 1\nreturn\n"
}
