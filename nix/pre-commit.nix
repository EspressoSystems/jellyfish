{ pkgs, ... }:

let
  nix-pre-commit-hooks = import (pkgs.fetchFromGitHub {
    owner = "cachix";
    repo = "pre-commit-hooks.nix";
    rev = "ff9c0b459ddc4b79c06e19d44251daa8e9cd1746";
    sha256 = "jlsQb2y6A5dB1R0wVPLOfDGM0wLyfYqEJNzMtXuzCXw=";
  });
in
nix-pre-commit-hooks.run {
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
    # The hook "clippy" that ships with nix-precommit-hooks is outdated.
    cargo-clippy = {
      enable = true;
      description = "Lint Rust code.";
      entry = "cargo-clippy";
      files = "\\.rs$";
      pass_filenames = false;
    };
  };
}
