// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/lsigsalt/lsigsalttest"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
)

// wireGenericGenerator drives svc's generic LogicSig generation through the
// real generator, against an algod that answers the TEAL compile with a
// program whose address is off the curve.
func wireGenericGenerator(t *testing.T, svc *Service) {
	t.Helper()
	program := lsigsalttest.OffCurve(t, []byte{8, 0x81, 0}, 2)
	generator := GenericLSigGenerator{
		Config: &serverconfig.ServerConfig{
			TEALCompileNetwork: "testnet",
			Algod:              apconfig.AlgodConfig{"testnet": {Server: "http://mock-algod"}},
		},
		MakeAlgod: func(string, string) (*algod.Client, error) {
			return algod.MakeClientWithTransport("http://mock-algod", "", nil, falconCompileMockTransport{bytecode: program.Bytecode, hash: program.Address.String()})
		},
		AuditLog: svc.AuditLog,
	}
	svc.GenerateGenericLSig = func(ctx context.Context, keyType string, params map[string]string) (string, error) {
		return generator.GenerateContext(ctx, svc.Runtime, keyType, params)
	}
}

// A generic LogicSig generation writes the key and audits it before its
// reload, so a reload that fails is answered beside the address: one that
// entered recovery, for a content defect, answers recovery_blocked with the
// cause and leaves the signer in recovery; one that kept the view in service
// answers a failed refresh, with the view, which does not hold the new key,
// still serving. Before this test only the integration suite reached the
// generator's reload.
func TestAGenericLogicSigGenerationAnswersItsReload(t *testing.T) {
	transient := errors.New("injected read failure")
	defect := fmt.Errorf("%w: injected", signertemplates.ErrGenerationValidation)
	owner := map[string]string{"owner": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}
	for _, tc := range []struct {
		name     string
		buildErr error
		want     string // the answer's kind, state and keys served
	}{
		{name: "the reload publishes", want: "ok unlocked keys=1"},
		{name: "a transient failure keeps the view", buildErr: transient, want: string(ErrorCacheRefresh) + " unlocked keys=0"},
		{name: "a content defect enters recovery", buildErr: defect, want: string(ErrorRecoveryBlocked) + " recovery keys=0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registerServiceGenericTemplate(t)
			ir := setupProductRuntime(t)
			installServiceGenericTemplate(t, ir)
			audit := &auditRecorder{}
			svc := Service{Runtime: ir, AuditLog: audit}
			wireGenericGenerator(t, &svc)
			if tc.buildErr != nil {
				ir.SetBuildFunc(func(kr *crypto.Keyring) (*productruntime.Loaded, error) {
					loaded, err := scanBuildForTest(ir, kr)
					if err != nil {
						return loaded, err
					}
					return loaded, tc.buildErr
				}, productruntime.ReloadEffects{})
			}

			result, svcErr := svc.GenerateKey(context.Background(), serviceGenericKeyType, owner)
			if result == nil || result.Address == "" || result.KeyType != serviceGenericKeyType {
				t.Fatalf("GenerateKey() = %#v, %#v; want the written key's address beside any answer", result, svcErr)
			}
			kind := "ok"
			if svcErr != nil {
				kind = string(svcErr.Kind)
			}
			if got := fmt.Sprintf("%s %v keys=%d", kind, ir.GetState(), ir.KeyCount()); got != tc.want {
				t.Fatalf("GenerateKey() answered %q (%#v); want %q", got, svcErr, tc.want)
			}
			if len(audit.generated) != 1 || audit.generated[0].address != result.Address {
				t.Fatalf("audited generations %+v, want the one key %s", audit.generated, result.Address)
			}
		})
	}
}
