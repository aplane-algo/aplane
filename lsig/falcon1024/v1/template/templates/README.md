# Embedded Falcon-1024 Templates

Place `.yaml` template files in this directory to compile them into the binary via `go:embed`.

Each template combines the Falcon-1024 DSA base with a parameterized TEAL suffix and is automatically registered with the logicsigdsa registry at startup.

See the package documentation in `provider.go` for the YAML schema and an example template.
