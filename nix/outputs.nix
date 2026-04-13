
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

  cargoArtifacts = craneLib.buildDepsOnly (rustCommonArgs // {
    pname = "hello-world";
    version = "0.1.0";
  });

  # Rust based executables

  rust-hello-world = craneLib.buildPackage (rustCommonArgs // {
    inherit cargoArtifacts;
    copyLibs = true;
    cargoExtraArgs = "--bin hello-world";
    pname = "hello-world";
    version = "0.1.0";
  });

  # Haskell.nix based executables

  packages = {
    plutus-midnight-zk-main = project.flake'.packages."plutus-midnight-zk:exe:main";
    rust-midnight-zk = rust-hello-world;
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
  inherit devShells;
  inherit hydraJobs;
}
