# ESP Agent SDK

Build compliance scanners using [Endpoint State Policy (ESP)](https://github.com/CurtisSlone/Endpoint-State-Policy).

## Overview

The ESP Agent SDK provides the tools to build scanners that execute ESP policies against endpoint systems. It includes reference implementations for common CTN (Collection Type Name) types and a ready-to-use CLI agent.

```
┌─────────────────────────────────────────────────────────────┐
│                     ESP Agent SDK                           │
├─────────────────────────────────────────────────────────────┤
│  agent/         CLI scanner application                     │
│  contract_kit/  Reference collectors, executors, contracts  │
├─────────────────────────────────────────────────────────────┤
│                  ESP Core (external)                        │
│  common, compiler, execution_engine                         │
└─────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Description |
|-------|-------------|
| [`agent`](./agent/README.md) | CLI application for scanning ESP policies |
| [`contract_kit`](./contract_kit/README.md) | Reference implementations and high-level scan API |

## Quick Start

### Build

```bash
make build          # Build all crates
make release        # Build optimized release
```

### Run

```bash
make run ESP=policy.esp                    # Scan single policy
make run-batch ESP=/path/to/policies/      # Scan directory
make run-full ESP=policy.esp               # Output full results to JSON
```

### Cross-Compilation

```bash
make build-win      # Windows (x86_64-pc-windows-gnu)
make build-musl     # Linux static (x86_64-unknown-linux-musl)
make release-all    # All targets, release mode
```

### Development

```bash
make test           # Run tests
make lint           # Run clippy (strict)
make check-all      # Check all targets compile
make pre-commit     # Format, lint, test
```

## Guides

| Guide | Description |
|-------|-------------|
| [ESP Language Guide](./guides/ESP_Language_Guide.md) | Learn to write ESP policies |
| [Contract Development Guide](./guides/Contract_Development_Guide.md) | Extend with custom CTN types |

## Requirements

- Rust 1.85+
- For cross-compilation: `mingw-w64` (Windows), `musl-tools` (static Linux)

### Development Environment

**VS Code DevContainers (recommended):**

Open the repository in VS Code and select "Reopen in Container" when prompted. This provides a fully configured environment with all cross-compilation toolchains.

**Manual Docker:**

```bash
make docker-build
```

## License

Apache 2.0
