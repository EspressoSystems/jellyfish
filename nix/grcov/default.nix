{ lib, rustToolchain, rustPlatform, fetchFromGitHub }:

rustPlatform.buildRustPackage rec {
  pname = "grcov";
  version = "v0.8.2";

  # See https://nixos.org/manual/nixpkgs/stable/#using-community-rust-overlays
  nativeBuildInputs = [
    rustToolchain
  ];

  doCheck = false;

  src = fetchFromGitHub {
    owner = "mozilla";
    repo = pname;
    rev = version;
    sha256 = "t1Gj5u4MmXPbQ5jmO9Sstn7aXJ6Ge+AnsmmG2GiAGKE=";
  };

  cargoSha256 = "DRAUeDzNUMg0AGrqU1TdrqBZJw4A2o3YJB0MdwwzefQ=";

  meta = with lib; {
    description = "grcov collects and aggregates code coverage information for multiple source files.";
    homepage = "https://github.com/mozilla/grcov";
    license = licenses.mpl20;
  };
}
