{
  description = "wsc - WebAssembly Signature Component";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ] (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable."1.90.0".default.override {
          extensions = [ "rustfmt" "clippy" "rust-src" "rust-analyzer" ];
          targets = [ "wasm32-wasip2" ];
        };

        # Common build inputs for all platforms
        commonBuildInputs = with pkgs; [
          openssl
        ];

        # Common native build inputs for all platforms
        commonNativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          cargo-fuzz
          cargo-audit
          cargo-deny
        ];

        # Platform-specific inputs
        # On Darwin, Security and SystemConfiguration frameworks are provided
        # by the default SDK in stdenv; only libiconv needs to be explicit.
        darwinBuildInputs = with pkgs; [
          libiconv
        ];

        linuxBuildInputs = with pkgs; [
          # libtss2-dev equivalent for optional TPM2 feature
        ];

        platformBuildInputs =
          if pkgs.stdenv.isDarwin then darwinBuildInputs
          else linuxBuildInputs;

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = commonBuildInputs ++ platformBuildInputs;
          nativeBuildInputs = commonNativeBuildInputs ++ [
            pkgs.bazel_8
          ];

          shellHook = ''
            export RUST_SRC_PATH="${rustToolchain}/lib/rustlib/src/rust/library"
            # Let Bazel accept the nixpkgs-provided version instead of .bazelversion pin
            export USE_BAZEL_VERSION="${pkgs.bazel_8.version}"
          '';
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "wsc";
          version = "0.7.0";
          src = ./.;

          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = commonBuildInputs ++ platformBuildInputs;

          # Build only the CLI binary
          cargoBuildFlags = [ "--package" "wsc-cli" ];
          cargoTestFlags = [ "--package" "wsc-cli" ];

          meta = with pkgs.lib; {
            description = "WebAssembly Signature Component - WASM signing and verification toolkit";
            homepage = "https://github.com/pulseengine/wsc";
            license = licenses.mit;
          };
        };
      }
    );
}
