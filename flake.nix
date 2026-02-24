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
        pkgsAllowUnfree = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
        gcc11 = pkgs.overrideCC pkgs.stdenv pkgs.gcc11;
        nightlyToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain:
          toolchain.minimal.override { extensions = [ "rustfmt" ]; });

        stableToolchain = pkgs.rust-bin.stable.latest.minimal.override {
          extensions = [ "clippy" "llvm-tools-preview" "rust-src" ];
          targets = [ "wasm32-unknown-unknown" ];
        };
        # A script that calls nightly cargo if invoked with `+nightly`
        # as the first argument, otherwise it calls stable cargo.
        cargo-with-nightly = pkgs.writeShellScriptBin "cargo" ''
          if [[ "$1" == "+nightly" ]]; then
            shift
            # Prepend nightly toolchain directory containing cargo, rustc, etc.
            exec env PATH="${nightlyToolchain}/bin:$PATH" cargo "$@"
          fi
          exec ${stableToolchain}/bin/cargo "$@"
        '';
        baseShell = with pkgs;
          clang15Stdenv.mkDerivation {
            name = "clang15-nix-shell";
            buildInputs = [
              argbash
              openssl
              pkg-config
              git
              nixpkgs-fmt

              cargo-with-nightly
              stableToolchain
              nightlyToolchain
              cargo-sort
              clang-tools_15
              clangStdenv
              llvm_15
              typos
              # grcov # TODO uncomment this line after https://github.com/mozilla/grcov/issues/1187#issuecomment-2252214718
            ];

            CARGO_TARGET_DIR = "target/nix_rustc";

            shellHook = ''
              export RUST_BACKTRACE=full
              export PATH="$PATH:$(pwd)/target/debug:$(pwd)/target/release"
              # Prevent cargo aliases from using programs in `~/.cargo` to avoid conflicts with local rustup installations.
              export CARGO_HOME=$HOME/.cargo-nix

              # Ensure `cargo fmt` uses `rustfmt` from nightly.
              export RUSTFMT="${nightlyToolchain}/bin/rustfmt"

              export C_INCLUDE_PATH="${llvmPackages_15.libclang.lib}/lib/clang/${llvmPackages_15.libclang.version}/include"
              export LIBCLANG_PATH=
              export CC="${clang-tools_15.clang}/bin/clang"
              export CXX="${clang-tools_15.clang}/bin/clang++"
              export AR="${llvm_15}/bin/llvm-ar"
              export CFLAGS="-mcpu=generic"

              # by default choose u64_backend
              export RUSTFLAGS='--cfg curve25519_dalek_backend="u64"'
            ''
              # install pre-commit hooks
              + self.check.${system}.pre-commit-check.shellHook;
          };
      in with pkgs; {
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
        # extra dev shells
        devShells = {
          # run with `nix develop .#cudaShell`
          cudaShell =
            let cudatoolkit = pkgsAllowUnfree.cudaPackages_12_3.cudatoolkit;
            in baseShell.overrideAttrs (oldAttrs: {
              # for GPU/CUDA env (e.g. to run ICICLE code)
              name = "cuda-env-shell";
              buildInputs = oldAttrs.buildInputs
                ++ [ cmake cudatoolkit util-linux gcc11 ];
              # CXX is overridden to use gcc as icicle-curves's build scripts need them
              shellHook = oldAttrs.shellHook + ''
                export PATH="${pkgs.gcc11}/bin:${cudatoolkit}/bin:${cudatoolkit}/nvvm/bin:$PATH"
                export LD_LIBRARY_PATH=${cudatoolkit}/lib
                export CUDA_PATH=${cudatoolkit}
                export CPATH="${cudatoolkit}/include"
                export LIBRARY_PATH="$LIBRARY_PATH:/lib"
                export CMAKE_CUDA_COMPILER=$CUDA_PATH/bin/nvcc
                export LIBCLANG_PATH=${llvmPackages_15.libclang.lib}/lib
                export CFLAGS=""
              '';
            });
        };
      });
}
