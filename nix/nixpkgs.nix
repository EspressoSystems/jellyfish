# Behaves like `<nixpkgs>` but pinned. Like `<nixpkgs>`, requires attrset for opt overlays.
attrs:
let
  hostpkgs = import <nixpkgs> {};
  pinnedNixpkgs = hostpkgs.lib.importJSON ./nixpkgs.json;
  nixpkgs = builtins.fetchTarball {
    url = pinnedNixpkgs.url;
    sha256 = pinnedNixpkgs.sha256;
  };
in import nixpkgs attrs
