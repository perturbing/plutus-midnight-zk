
{ inputs, system }:

let
  inherit (pkgs) lib;

  pkgs = import ./pkgs.nix { inherit inputs system; };

  utils = import ./utils.nix { inherit pkgs lib; };

  project = import ./project.nix { inherit inputs pkgs lib; };

  mkShell = ghc: import ./shell.nix { inherit inputs pkgs lib project utils ghc rustToolchain; };

  # Rust / crane setup (mirrors the original flake-parts configuration.nix)
  rustToolchain = inputs.fenix.packages.${system}.combine (with inputs.fenix.packages.${system}; [
    minimal.rustc
    minimal.cargo
    targets.x86_64-unknown-linux-musl.latest.rust-std
  ]);

  craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;

  rustCommonArgs = {
    src = craneLib.cleanCargoSource ../.;
    strictDeps = true;
    doCheck = false;
  } // lib.optionalAttrs (system == "x86_64-linux") {
    CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
    CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
  };

  rustPkg = { pname = "rust-midnight-zk"; version = "0.1.0"; };

  cargoArtifacts = craneLib.buildDepsOnly (rustCommonArgs // rustPkg);

  # Rust based executables

  rust-midnight-zk = craneLib.buildPackage (rustCommonArgs // rustPkg // {
    inherit cargoArtifacts;
    copyLibs = true;
    cargoExtraArgs = "--bin write-test-vectors";
  });

  # Haskell.nix based executables

  packages = {
    plutus-midnight-zk-run-vector-test = project.flake'.packages."plutus-midnight-zk:test:run-vector-test";
    rust-midnight-zk-write-test-vectors = rust-midnight-zk;
  };

  apps = {
    plutus-midnight-zk-run-vector-test =
      let
        testBin = project.flake'.packages."plutus-midnight-zk:test:run-vector-test";
        # The test binary resolves test vectors as "../test-vectors/" relative to
        # its CWD, so it must run from the plutus-midnight-zk/ subdirectory.
        # When invoked from the repo root (the common case for `nix run`), step
        # into that subdirectory first; when already there, run in place.
        wrapper = pkgs.writeShellScript "run-vector-test" ''
          if [ -d "plutus-midnight-zk" ]; then
            cd plutus-midnight-zk
          fi
          exec "${testBin}/bin/run-vector-test" "$@"
        '';
      in
      {
        type = "app";
        program = "${wrapper}";
      };
    rust-midnight-zk-write-test-vectors = {
      type = "app";
      program = "${rust-midnight-zk}/bin/write-test-vectors";
    };
  };

  devShells = rec {
    default = ghc966;
    ghc966  = mkShell "ghc966";
    ghc984  = mkShell "ghc984";
    ghc9102 = mkShell "ghc9102";
    ghc9122 = mkShell "ghc9122";
  };

  projectFlake = project.flake {};

  defaultHydraJobs = {
    ghc966  = projectFlake.hydraJobs.ghc966;
    ghc984  = projectFlake.hydraJobs.ghc984;
    ghc9102 = projectFlake.hydraJobs.ghc9102;
    ghc9122 = projectFlake.hydraJobs.ghc9122;
    inherit packages;
    inherit devShells;
    required = utils.makeHydraRequiredJob hydraJobs;
  };

  hydraJobsPerSystem = {
    "x86_64-linux"  = defaultHydraJobs;
    "x86_64-darwin" = defaultHydraJobs;
    "aarch64-linux" = defaultHydraJobs;
    "aarch64-darwin" = defaultHydraJobs;
  };

  hydraJobs = utils.flattenDerivationTree "-" hydraJobsPerSystem.${system};
in

{
  inherit packages;
  inherit apps;
  inherit devShells;
  inherit hydraJobs;
}
