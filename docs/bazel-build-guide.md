# Building sigil with Bazel

This document describes how to build sigil as WebAssembly components using Bazel and `rules_wasm_component`.

## Architecture

The sigil project supports dual build systems:

- **Cargo (Native)**: Build native binaries with full features including GitHub key fetching
- **Bazel (WASM)**: Build WebAssembly components for hermetic, cross-platform execution

### Component Structure

```
sigil/
├── src/lib/              # Core signing library (Rust)
├── src/component/        # WASM component exporting WIT interface
├── src/cli/              # Command-line interface (native and WASI)
└── wit/                  # WIT interface definitions
```

### Build Targets

| Target | Output | Description |
|--------|--------|-------------|
| `//src/lib:wsc` | Rust library | Core signing functionality |
| `//wit:wasmsign_wit` | WIT interface | Component model interface |
| `//src/component:signing_lib` | `signing-lib.wasm` | Reusable component exporting signing interface |
| `//src/cli:wasmsign_cli` | `wasmsign-cli.wasm` | WASI CLI tool |

## Building with Cargo (Native)

Build the native CLI with all features:

```bash
cargo build --release
./target/release/sigil --help
```

This includes:
- ✅ GitHub public key fetching (`--from-github` flag)
- ✅ HTTP client (ureq)
- ✅ All subcommands (keygen, sign, verify, etc.)

## Building with Bazel (WASM)

Build WebAssembly components:

```bash
# Build signing library component
bazel build //src/component:signing_lib

# Build CLI component (WASI)
bazel build //src/cli:wasmsign_cli
```

This produces:
- ✅ Hermetic WASM components
- ✅ Cross-platform execution in Wasmtime
- ✅ GitHub key fetching via wasi:http (enabled)
- ✅ Reusable WIT interface

## Feature Differences

### Native Build (Cargo)
- ✅ GitHub key fetching via `--from-github` (using ureq HTTP client)
- ✅ Native performance
- ✅ System dependencies (OpenSSL, etc.)
- ❌ Platform-specific binaries

### WASM Build (Bazel)
- ✅ Hermetic execution (no system dependencies)
- ✅ Cross-platform (runs on any Wasmtime host)
- ✅ Reusable component interface (WIT)
- ✅ Browser-compatible via jco
- ✅ GitHub key fetching via `--from-github` (using wasi:http/outgoing-handler)
- ✅ Full feature parity with native builds

## Integration with rules_wasm_component

To use sigil components in `rules_wasm_component`:

1. **Reference the sigil repository** in your MODULE.bazel:
   ```starlark
   git_override(
       module_name = "wsc",
       remote = "https://github.com/pulseengine/sigil.git",
       commit = "<commit-hash>",
   )
   ```

2. **Use the signing component** in your BUILD files:
   ```starlark
   load("@wsc//src/component:defs.bzl", "signing_lib")

   # Use the signing component in your workflow
   wasm_sign(
       name = "signed_component",
       component = ":my_component",
       key = ":signing_key",
   )
   ```

3. **Use the CLI tool** in hermetic signing workflows:
   ```starlark
   genrule(
       name = "sign_module",
       srcs = [":my_module.wasm"],
       outs = ["signed_module.wasm"],
       cmd = """
           $(location @wsc//src/cli:wasmsign_cli) sign \
               --input-file $(location :my_module.wasm) \
               --output-file $@ \
               --secret-key $(location :key.sec)
       """,
       tools = ["@wsc//src/cli:wasmsign_cli"],
   )
   ```

## WIT Interface

The signing component exports the following interface:

```wit
interface signing {
    // Key generation
    keygen: func() -> result<key-pair, string>;

    // Signing operations
    sign: func(
        module-bytes: list<u8>,
        secret-key: list<u8>,
        public-key: option<list<u8>>,
        options: sign-options
    ) -> result<sign-result, string>;

    // Verification operations
    verify: func(
        module-bytes: list<u8>,
        public-key: list<u8>,
        detached-sig: option<list<u8>>
    ) -> result<bool, string>;

    // Key format conversion
    parse-public-key: func(key-bytes: list<u8>) -> result<list<u8>, string>;
    parse-secret-key: func(key-bytes: list<u8>) -> result<list<u8>, string>;
    to-pem-public: func(key-bytes: list<u8>) -> result<string, string>;
    to-pem-secret: func(key-bytes: list<u8>) -> result<string, string>;
}
```

## Testing

### Native Tests
```bash
cargo test
```

### Component Tests
```bash
bazel test //src/component:signing_lib_test
bazel test //src/cli:wasmsign_cli_test
```

## Dependencies

### Cargo Dependencies
- `ed25519-compact` - EdDSA signatures
- `ct-codecs` - Constant-time encoding
- `anyhow`, `thiserror` - Error handling
- `clap` - CLI parsing
- `ureq`, `uri_encode` - HTTP client for native builds (optional)
- `wasi` - WASI Preview 2 bindings including wasi:http (optional)

### Bazel Dependencies
- `rules_rust` - Rust toolchain
- `rules_wasm_component` - Component model support
- `@crates` - Rust crate dependencies (via crate_universe)

## Contributing

When adding features:

1. **Maintain dual build support**: Ensure both Cargo and Bazel builds work
2. **Target-based conditional compilation**: Use `#[cfg(target_os = "wasi")]` for WASI-specific code
   - Native builds (`#[cfg(not(target_os = "wasi"))]`): Use standard Rust libraries (ureq, etc.)
   - WASI builds (`#[cfg(target_os = "wasi")]`): Use wasi crate interfaces (wasi::http, etc.)
3. **No feature flags needed**: HTTP client selection is automatic based on target platform
4. **HTTP client abstraction**: Maintain separate implementations for native (ureq) and WASI (wasi::http)
5. **Document changes**: Update this README and component WIT interface

## License

MIT License - See LICENSE file for details
