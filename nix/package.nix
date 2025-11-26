{
  pkgs,
  crane,
  root,
}: let
  craneLib = crane.mkLib pkgs;
  base = root + /server;
  commonArgs = {
    pname = "flare";
    version = "latest";
    src = pkgs.lib.fileset.toSource {
      root = base;
      fileset = pkgs.lib.fileset.unions [
        (base + /Cargo.toml)
        (base + /Cargo.lock)
        (base + /flare)
        (base + /flare-sim)
        (base + /flare-test)
        (base + /sea-entity)
        (base + /sea-migration)
      ];
    };
  };

  flare-deps = craneLib.buildDepsOnly (commonArgs
    // {
      nativeBuildInputs = with pkgs; [
        pkgs.python3
        pkgs.gcc
      ];
    });

  flare = craneLib.buildPackage (commonArgs
    // {
      cargoArtifacts = flare-deps;
      cargoBuildCommand = "cargo build --release --bin flare";
      cargoTestCommand = "cargo test --release -p flare";
    });
in
  flare
