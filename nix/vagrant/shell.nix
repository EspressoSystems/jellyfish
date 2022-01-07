with import ../nixpkgs.nix { };

mkShell {
  buildInputs = [
    vagrant
  ];
}
