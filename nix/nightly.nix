let
  basePkgs = import ./nixpkgs.nix { };

  rust_overlay = with basePkgs; import (fetchFromGitHub
    (lib.importJSON ./oxalica_rust_overlay.json));

  pkgs = import ./nixpkgs.nix { overlays = [ rust_overlay ]; };

  nightlyToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.minimal);
  grcov = with pkgs; callPackage ./grcov { rustToolchain = nightlyToolchain; };
in
with pkgs;

mkShell {
  buildInputs = [
    nightlyToolchain
    grcov
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
  ];

  shellHook = ''
    export RUST_BACKTRACE=full
  '';
}
