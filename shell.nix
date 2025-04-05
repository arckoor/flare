{
  pkgs ?
    import <nixpkgs> {
      overlays = [
        (import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz"))
      ];
    },
}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    (rust-bin.stable.latest.default.override {
      extensions = [
        "llvm-tools-preview"
      ];
    })

    cargo-llvm-cov
    cargo-nextest
    sea-orm-cli

    openssl
    pkg-config

    postgresql
    redis
  ];

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

  shellHook = ''
    alias cclean="cargo clean";
    alias cbuild="cargo build";
    alias ctest="cargo nextest run --workspace";
    alias cfmt="cargo fmt";
    alias cclippy="cargo clippy -- -D warnings";
    alias gen="sea-orm-cli generate entity -u postgres://flare:12345@localhost:5432/flare-db-test -o sea-entity/src --lib --with-serde both --with-copy-enums";
    alias mig="sea-orm-cli migrate -d sea-migration generate"

    export NIX_SHELL_DIR="$PWD/.nix-shell"
    export PGDATA="$NIX_SHELL_DIR/postgres"
    export REDIS_DATA="$NIX_SHELL_DIR/redis"

    export DATABASE_BASE=postgres://flare:12345@localhost:5432

    if ! test -d $PGDATA; then
      pg_ctl initdb -D  $PGDATA
    fi

    HOST_COMMON="host\s\+all\s\+all"
    sed -i "s|^$HOST_COMMON.*127.*$|host all all 127.0.0.1/32 trust|" $PGDATA/pg_hba.conf
    sed -i "s|^$HOST_COMMON.*::1.*$|host all all ::1/128 trust|"      $PGDATA/pg_hba.conf

    pg_ctl                                                  \
    -D $PGDATA                                              \
    -l $PGDATA/postgres.log                                 \
    -o "-c unix_socket_directories='$PGDATA'"               \
    -o "-c listen_addresses='localhost'"                    \
    -o "-c log_destination='stderr'"                        \
    -o "-c logging_collector=on"                            \
    -o "-c log_directory='log'"                             \
    -o "-c log_filename='postgresql-%Y-%m-%d_%H-%M-%S.log'" \
    -o "-c log_min_messages=info"                           \
    -o "-c log_min_error_statement=info"                    \
    -o "-c log_connections=on"                              \
    start

    psql -h $PGDATA -d postgres -c "CREATE USER flare WITH PASSWORD '12345' CREATEDB;"
    psql -h $PGDATA -d postgres -c "CREATE DATABASE \"flare-db\" OWNER flare;"
    psql -h $PGDATA -d postgres -c "CREATE DATABASE \"flare-db-test\" OWNER flare;"

    if ! test -d $REDIS_DATA; then
      mkdir -p $REDIS_DATA
    fi

    redis-server --daemonize yes --protected-mode no --port 6379 --dir $REDIS_DATA --appendonly yes

    trap 'pg_ctl -D $PGDATA stop 2> /dev/null && redis-cli -h localhost -p 6379 shutdown 2> /dev/null' EXIT
  '';
}
