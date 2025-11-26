{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
  };

  outputs = {
    nixpkgs,
    rust-overlay,
    crane,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachSystem [flake-utils.lib.system.x86_64-linux] (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        schemathesis = import ./nix/schemathesis.nix {inherit pkgs;};
        shellScripts = import ./nix/scripts.nix {inherit pkgs;};
        flare = import ./nix/package.nix {
          inherit pkgs crane;
          root = ./.;
        };
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs;
            [
              (rust-bin.stable.latest.default.override {
                extensions = ["llvm-tools-preview"];
              })

              cargo-audit
              cargo-edit
              cargo-llvm-cov
              cargo-nextest
              sea-orm-cli
              schemathesis

              botan3
              openssl
              python313

              postgresql_18
              valkey
            ]
            ++ shellScripts;

          RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

          shellHook = ''
            export NIX_SHELL_DIR="$PWD/.nix-shell"
            export PGDATA="$NIX_SHELL_DIR/postgres"
            export VALKEY_DATA="$NIX_SHELL_DIR/valkey"

            export PG_BASE=postgres://flare:12345@localhost:5432
            export PG_PASSWORD=12345
            unset CI
          '';
        };

        packages.default = pkgs.dockerTools.buildImage {
          name = "flare";
          tag = "latest";
          created = "now";
          copyToRoot = pkgs.buildEnv {
            name = "image-root";
            paths = [flare];
            pathsToLink = ["/bin" "/flare"];
          };

          config = {
            WorkingDir = "/flare";
            Cmd = ["flare"];
          };
        };
      }
    );
}
