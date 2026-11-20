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

  outputs = { self, nixpkgs, flake-utils, rust-overlay, pre-commit-hooks, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        # keep in sync with NIGHTLY in .github/workflows/build.yml and justfile
        nightlyToolchain = pkgs.rust-bin.nightly."2026-11-16".minimal.override {
          extensions = [ "rustfmt" ];
        };

        stableToolchain = pkgs.rust-bin.stable.latest.minimal.override {
          extensions = [ "clippy" "llvm-tools-preview" "rust-src" ];
          targets = [ "wasm32-unknown-unknown" ];
        };
        # A script that calls nightly cargo if invoked with `+nightly` or
        # `+nightly-<date>` as the first argument, otherwise it calls stable cargo.
        cargo-with-nightly = pkgs.writeShellScriptBin "cargo" ''
          if [[ "$1" == +nightly* ]]; then
            shift
            # Prepend nightly toolchain directory containing cargo, rustc, etc.
            exec env PATH="${nightlyToolchain}/bin:$PATH" cargo "$@"
          fi
          exec ${stableToolchain}/bin/cargo "$@"
        '';
        baseShell = with pkgs;
          clangStdenv.mkDerivation {
            name = "clang-nix-shell";
            buildInputs = [
              argbash
              openssl
              pkg-config
              git
              nixpkgs-fmt

              cargo-with-nightly
              stableToolchain
              nightlyToolchain
              cargo-audit
              cargo-nextest
              just
              cargo-sort
              clang-tools
              clangStdenv
              llvm
              typos
              # grcov # TODO uncomment this line after https://github.com/mozilla/grcov/issues/1187#issuecomment-2252214718
            ];

            CARGO_TARGET_DIR = "target/nix_rustc";
            # unsupported by clang for wasm32 (blst)
            hardeningDisable = [ "zerocallusedregs" ];

            shellHook = ''
              export RUST_BACKTRACE=full
              export PATH="$PATH:$(pwd)/target/debug:$(pwd)/target/release"
              # Prevent cargo aliases from using programs in `~/.cargo` to avoid conflicts with local rustup installations.
              export CARGO_HOME=$HOME/.cargo-nix

              # Ensure `cargo fmt` uses `rustfmt` from nightly.
              export RUSTFMT="${nightlyToolchain}/bin/rustfmt"

              export C_INCLUDE_PATH="${llvmPackages.libclang.lib}/lib/clang/${lib.versions.major llvmPackages.libclang.version}/include"
              export LIBCLANG_PATH=
              export CC="${llvmPackages.clang}/bin/clang"
              export CXX="${llvmPackages.clang}/bin/clang++"
              export AR="${llvm}/bin/llvm-ar"
              export CFLAGS_wasm32_unknown_unknown="-mcpu=generic"

              # by default choose u64_backend
              export RUSTFLAGS='--cfg curve25519_dalek_backend="u64"'
            ''
            # install pre-commit hooks
            + self.check.${system}.pre-commit-check.shellHook;
          };
      in
      with pkgs; {
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
              spell-check = {
                enable = true;
                description = "Spell check";
                entry = "typos";
                pass_filenames = false;
              };
              nixpkgs-fmt.enable = true;
            };
          };
        };
        devShell = baseShell;
      });
}
