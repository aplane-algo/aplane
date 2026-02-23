# Embedded Templates

Place `.yaml` template files in this directory to compile them into the binary via `go:embed`.

Templates are automatically loaded and registered with the genericlsig registry at startup.

See `examples/templates/` for reference template files (hashlock-v2, timelock-v2).
