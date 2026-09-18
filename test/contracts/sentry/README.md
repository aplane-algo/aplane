# Sentry public handoff fixtures

`enrollment_v1.json` is the canonical full-size
`aplane.sentry-enrollment.v1` composition fixture. It contains public metadata
only: one complete Falcon-1024 witness reference and one portable endpoint.

`internal/sentry/enrollment/contract_fixture_test.go` pins the file to the
production parser and stable serializer. The fixture is a public file-format
contract; it is not part of the HTTP SDK DTO surface.

`enrollment_import_result_v1.json` pins the structured batch-import result,
including the separately owned signer-reference and client-endpoint effects.
