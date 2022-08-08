let
  basePkgs = import ./nix/nixpkgs.nix { };

  rust_overlay = with basePkgs;
    import (fetchFromGitHub (lib.importJSON ./nix/oxalica_rust_overlay.json));

  pkgs = import ./nix/nixpkgs.nix { overlays = [ rust_overlay ]; };

  nightlyToolchain = pkgs.rust-bin.selectLatestNightlyWith
    (toolchain: toolchain.minimal.override { extensions = [ "rustfmt" ]; });

  stableToolchain = pkgs.rust-bin.stable.latest.minimal.override {
    extensions = [ "clippy" "llvm-tools-preview" "rust-src" ];
  };

  pre-commit-check = pkgs.callPackage ./nix/pre-commit.nix { };
in with pkgs;

mkShell {
  buildInputs = [
    argbash
    openssl
    pkgconfig
    git

    stableToolchain
    nightlyToolchain

  ] ++ lib.optionals stdenv.isDarwin [ darwin.apple_sdk.frameworks.Security ];

  shellHook = ''
    export RUST_BACKTRACE=full
    export PATH="$PATH:$(pwd)/target/debug:$(pwd)/target/release"

    # Ensure `cargo fmt` uses `rustfmt` from nightly.
    export RUSTFMT="${nightlyToolchain}/bin/rustfmt"

    # install pre-commit hooks
    ${pre-commit-check.shellHook}
  '';
}
