# Policy verdict fixtures

Each file holds cases in the `aplane.policy-verdicts.v1` format: a policy
(fragments merged onto a minimal or the shipped document), a group, how the
signer sees each position, and what the signer decided.

The expectations were recorded from the signing code itself, before its
verdict logic is extracted into a shared evaluator. They freeze today's
behavior: the outcome, the review or approval rule, and for a refusal its
error kind and exact text, which carries the violation order and transaction
numbers.

`TestVerdictFixtures` in `internal/signerapp/signing/verdict_fixtures_test.go`
runs every case through the real signing path named by its `surface` and
documents the case fields. To re-record after an intended behavior change:

```bash
go test ./internal/signerapp/signing -run TestVerdictFixtures -update-verdicts
```

Review the resulting diff: a changed expectation is a changed verdict.

These fixtures are an in-repo contract. The SDKs do not consume them.
