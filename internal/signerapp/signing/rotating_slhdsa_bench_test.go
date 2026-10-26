// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type slhBenchmarkConsole struct{}

func (slhBenchmarkConsole) Printf(string, ...any) {}
func (slhBenchmarkConsole) Println(...any)        {}
func (slhBenchmarkConsole) Sync()                 {}

// slhDiskFixture includes real encrypted credential reads and full stage-zero
// validation. Chain reads and approval/audit use the service test adapters;
// timings exclude RPC latency, human approval, audit fsync and daemon pacing.
func slhDiskFixture(b *testing.B) (*rotatingFixture, *keystore.FileKeyStore) {
	b.Helper()
	f, _ := newSigningFixtureFor(b, slhTestType)
	f.svc.Console = slhBenchmarkConsole{}
	f.svc.Planner.Console = slhBenchmarkConsole{}
	f.svc.Approval.Console = slhBenchmarkConsole{}
	paths := storepaths.NewPaths(f.root)
	passphrase := []byte("slh-lifecycle-benchmark-only")
	defer clear(passphrase)
	kr, active := genstoretest.MintFirstAtomic(b, paths, passphrase)
	defer kr.Zero()
	var seed rotatinghybrid.Seed
	copy(seed[:], f.secret.Seed)
	defer seed.Zero()
	var genesis [32]byte
	copy(genesis[:], rotatingTestGenesis)
	payload, _, err := slhTestType.newKeyPayload(&seed, genesis)
	if err != nil {
		b.Fatal(err)
	}
	defer payload.ZeroSecrets()
	if _, err := keys.SavePayloadActive(active, payload, kr); err != nil {
		b.Fatal(err)
	}
	store := keystore.NewAtomicFileKeyStoreForPaths(paths)
	b.Cleanup(store.ClearKeys)
	if err := store.Unlock(passphrase); err != nil {
		b.Fatal(err)
	}
	if err := store.Scan(nil); err != nil {
		b.Fatal(err)
	}
	f.session.Destroy()
	f.session = keystore.NewKeySession(store)
	f.session.InitializeSession()
	b.Cleanup(f.session.Destroy)
	return f, store
}

// BenchmarkSLHLifecycle deliberately uses a small iteration count in the
// documented command: these are full operations, not primitive microbenchmarks.
func BenchmarkSLHLifecycle(b *testing.B) {
	b.Run("CredentialReadValidate", func(b *testing.B) {
		f, store := slhDiskFixture(b)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key, err := store.Get(context.Background(), f.account.String())
			if err != nil {
				b.Fatal(err)
			}
			key.Value.(*coresigning.RotatingKeyMaterial).Zero()
		}
	})
	b.Run("SuccessorSignAndVerify", func(b *testing.B) {
		f := newRotatingFixtureFor(b, slhTestType)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := f.ops.CheckStageOpens(f.secret, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
	for _, warm := range []bool{false, true} {
		state := "Cold"
		if warm {
			state = "Warm"
		}
		for _, sign := range []bool{false, true} {
			operation := "Prepare"
			if sign {
				operation = "PrepareAndSign"
			}
			b.Run(operation+state, func(b *testing.B) {
				f, _ := slhDiskFixture(b)
				request := signerapi.RotatingPrepareRequest{Account: f.account.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(f.spend(1000, 1100))}
				if warm {
					r := f.fill(b, StageFillOptions{Horizon: 4096})
					if r.Err != nil || r.Pending {
						b.Fatalf("warm preparation: %+v", r)
					}
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !warm {
						b.StopTimer()
						if err := f.tables.Discard(f.table(b)); err != nil {
							b.Fatal(err)
						}
						b.StartTimer()
					}
					prep, err := f.svc.PrepareRotatingWithContext(context.Background(), request, f.session)
					if err != nil {
						b.Fatal(err)
					}
					if sign {
						_, err := f.svc.SignRotatingWithContext(context.Background(), signerapi.RotatingSignRequest{Account: f.account.String(), Transactions: prep.Transactions}, f.session)
						if err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
	for _, stage := range []uint64{0, 8, 64} {
		for _, hinted := range []bool{false, true} {
			if stage == 0 && hinted {
				continue
			}
			b.Run(fmt.Sprintf("RestoreStage%d/Hint%t", stage, hinted), func(b *testing.B) {
				f, _ := slhDiskFixture(b)
				f.chain.authorizer = f.stageAddress(b, stage)
				passes := 0
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					if err := f.tables.Discard(f.table(b)); err != nil {
						b.Fatal(err)
					}
					f.lockGen++
					var hint *uint64
					if hinted {
						hint = &stage
					}
					if _, err := f.recovery().StartOperator(f.lockGen, f.account.String(), hint, 1, 1024, time.Hour); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
					for pass := 0; ; pass++ {
						if pass >= 128 {
							b.Fatal("recovery did not settle")
						}
						r := f.fill(b, StageFillOptions{Horizon: 4096})
						passes++
						if r.Err != nil {
							b.Fatal(r.Err)
						}
						if !r.Pending {
							if !r.Resolved || r.Stage != stage || r.Scanned != stage+3 {
								b.Fatalf("restore: %+v", r)
							}
							break
						}
					}
				}
				b.ReportMetric(float64(passes)/float64(b.N), "passes/op")
			})
		}
	}
}
