{
  description = "flare devshell";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
  };

  outputs = {
    nixpkgs,
    rust-overlay,
    flake-utils,
    ...
  } @ inputs:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        mkScript = name: text: (pkgs.writeShellScriptBin name text);

        shellScripts = [
          (mkScript "db-setup" ''
            if ! test -d $PGDATA; then
              pg_ctl initdb -D $PGDATA
            fi

            HOST_COMMON="host\s\+all\s\+all"
            sed -i "s|^$HOST_COMMON.*127.*$|host all all 127.0.0.1/32 trust|" $PGDATA/pg_hba.conf
            sed -i "s|^$HOST_COMMON.*::1.*$|host all all ::1/128 trust|"      $PGDATA/pg_hba.conf

            if ! test -d $VALKEY_DATA; then
              mkdir -p $VALKEY_DATA
            fi
          '')

          (mkScript "db-reset" ''
            db-stop
            rm -rf $PGDATA
            rm -rf $VALKEY_DATA
            db-start
          '')

          (mkScript "db-start" ''
            db-setup

            pg_ctl                                                  \
            -D $PGDATA                                              \
            -l $PGDATA/postgres.log                                 \
            -o "-c unix_socket_directories='$PGDATA'"               \
            -o "-c listen_addresses='localhost'"                    \
            start

            psql -h $PGDATA -d postgres -c "CREATE USER flare WITH PASSWORD '12345' CREATEDB;"
            psql -h $PGDATA -d postgres -c "CREATE DATABASE \"flare-db\" OWNER flare;"
            psql -h $PGDATA -d postgres -c "CREATE DATABASE \"flare-db-test\" OWNER flare;"

            valkey-server --daemonize yes --protected-mode no --port 6379 --dir $VALKEY_DATA --appendonly yes
          '')

          (mkScript "db-stop" ''
            pg_ctl -D $PGDATA stop 2> /dev/null
            valkey-cli -h localhost -p 6379 shutdown 2> /dev/null
          '')

          (mkScript "gen" ''
            sea-orm-cli generate entity \
              -u postgres://flare:12345@localhost:5432/flare-db-test \
              -o sea-entity/src \
              --lib \
              --with-prelude none \
              --with-serde both \
              --with-copy-enums \
              --enum-extra-derives 'Hash','utoipa::ToSchema' \
              --enum-extra-attributes 'serde(rename_all = "snake_case")'
          '')
          (mkScript "mig" "sea-orm-cli migrate -d sea-migration generate")
          (mkScript "cov" "cargo llvm-cov nextest --no-fail-fast --all --ignore-filename-regex '(sea-entity|sea-migration).*\.rs' --color always --html --open")

          (mkScript "ctest" "cargo nextest run --workspace")
          (mkScript "doc" "cargo run --bin api-doc > openapi.json")
        ];
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs;
            [
              (rust-bin.stable.latest.default.override {
                extensions = ["llvm-tools-preview"];
              })

              cargo-edit
              cargo-llvm-cov
              cargo-nextest
              sea-orm-cli

              botan3
              openssl
              python313

              postgresql
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
          '';
        };
      }
    );
}
