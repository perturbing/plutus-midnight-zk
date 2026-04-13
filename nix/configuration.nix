{ self, inputs, ...}: {
  perSystem = {system, pkgs, lib, ...}:

    let
      toolchain = with inputs.fenix.packages.${system};
        combine [
          minimal.rustc
          minimal.cargo
          targets.x86_64-unknown-linux-musl.latest.rust-std
        ];

      craneLib = (inputs.crane.mkLib pkgs).overrideToolchain toolchain;

      src = lib.cleanSource "${self}";

      commonArgs = {
        inherit src;
        strictDeps = true;
        doCheck = false;

        CARGO_BUILD_TARGET = if system == "x86_64-linux" then "x86_64-unknown-linux-musl" else null;
        CARGO_BUILD_RUSTFLAGS = if system == "x86_64-linux" then "-C target-feature=+crt-static" else null;
      };

      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

    in {
      packages.default = craneLib.buildPackage (commonArgs // {
        inherit cargoArtifacts;
        copyLibs = true;
      });
    };
}
