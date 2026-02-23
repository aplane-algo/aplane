# Core Plugins Directory

This directory contains **symlinks** to active core plugins that will be auto-detected and included when building algosh.

## No Core Plugins Enabled by Default

By default, algosh builds with **no core plugins** to keep the binary minimal and focused on core functionality.

## Core Plugin Repository

All core plugin source code is stored in `../coreplugins_repository/`:
- `selfping` - Send atomic group of zero-ALGO self-payments

The actual code never moves - enabling a core plugin creates a symlink from this directory to the code in `coreplugins_repository/`.

## Enabling a Plugin

Use the Makefile commands for easy plugin management:

```bash
# List all plugins (active and inactive)
make list-plugins

# Enable a specific plugin
make enable-selfping

# Enable multiple plugins
make enable-selfping

# Build with active plugins
make algosh-all

# Disable a plugin
make disable-selfping

# Disable all plugins
make disable-all
```

Or manually create a symlink:
```bash
ln -s ../coreplugins_repository/selfping selfping
make algosh-all
```

To set plugins as default (always included), edit Makefile:
```makefile
DEFAULT_PLUGINS := selfping
```

## Creating New Plugins

See `../doc/PLUGINS_README.md` for complete documentation on creating and managing plugins.

The plugin system automatically:
- Detects plugins in this directory
- Generates registration files
- Includes them in `make algosh-all`
