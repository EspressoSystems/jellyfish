# Copyright (c) 2022 Espresso Systems (espressosys.com)
# This file is part of the Jellyfish library.

# You should have received a copy of the MIT License
# along with the Jellyfish library. If not, see <https://mit-license.org/>.

{
  description = "Jellyfish dev env";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils"; # for dedup

  # allow shell.nix alongside flake.nix
  inputs.flake-compat.url = "github:edolstra/flake-compat";
  inputs.flake-compat.flake = false;

  inputs.rust-overlay.url = "github:oxalica/rust-overlay";
  inputs.pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";
  inputs.pre-commit-hooks.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, flake-utils, flake-compat, rust-overlay, pre-commit-hooks, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ 
          (import rust-overlay)
        ];
        pkgs = import nixpkgs { inherit system overlays; };
        nightlyToolchain = pkgs.rust-bin.selectLatestNightlyWith
          (toolchain: toolchain.minimal.override { extensions = [ "rustfmt" ]; });

        stableToolchain = pkgs.rust-bin.stable.latest.minimal.override {
          extensions = [ "clippy" "llvm-tools-preview" "rust-src" ];
          targets = ["wasm32-unknown-unknown"];
        };
      in with pkgs;
      {
        check = {
          pre-commit-check = pre-commit-hooks.lib.${system}.run {
            src = ./.;
            hooks = {
              check-format = {
                enable = true;
                files = "\\.rs$";
                entry = "cargo fmt -- --check";
              };
              doctest = {
                enable = true;
                entry = "cargo test --doc";
                files = "\\.rs$";
                pass_filenames = false;
              };
              cargo-clippy = {
                enable = true;
                description = "Lint Rust code.";
                entry = "cargo-clippy --workspace -- -D warnings";
                files = "\\.rs$";
                pass_filenames = false;
              };
              cargo-sort = {
                enable = true;
                description = "Ensure Cargo.toml are sorted";
                entry = "cargo sort -w";
                pass_filenames = false;
              };
            };
          };
        };
        devShell = clang15Stdenv.mkDerivation {
          name = "clang15-nix-shell";
          buildInputs = [
            argbash
            openssl
            pkgconfig
            git

            stableToolchain
            nightlyToolchain
            cargo-sort
            clang-tools_15
            clangStdenv
            llvm_15
          ] ++ lib.optionals stdenv.isDarwin [ darwin.apple_sdk.frameworks.Security ];

          shellHook = ''
            export RUST_BACKTRACE=full
            export PATH="$PATH:$(pwd)/target/debug:$(pwd)/target/release"

            # Ensure `cargo fmt` uses `rustfmt` from nightly.
            export RUSTFMT="${nightlyToolchain}/bin/rustfmt"

            export C_INCLUDE_PATH="${llvmPackages_15.libclang.lib}/lib/clang/${llvmPackages_15.libclang.version}/include"
            export CC="${clang-tools_15.clang}/bin/clang"
            export AR="${llvm_15}/bin/llvm-ar"
            export CFLAGS="-mcpu=generic"
          ''
          # install pre-commit hooks
          + self.check.${system}.pre-commit-check.shellHook;
        };
      }
    );
}
