{pkgs}: let
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

    (mkScript "fuzz" ''
      set -e

      cargo build --features fuzz --bin fuzz
      cargo run --features fuzz --bin fuzz >fuzz.log &
      p=$!
      trap 'kill -SIGINT "$p"' EXIT

      timeout=30
      elapsed=0
      until curl -s http://localhost:8080/api/ping >/dev/null 2>&1; do
          if [ "$elapsed" -ge "$timeout" ]; then
              echo "Server did not start within $timeout seconds."
              kill -SIGINT "$p"
              exit 1
          fi
          echo "Waiting for server..."
          sleep 1
          elapsed=$((elapsed + 1))
      done
      curl -X POST -H 'Content-Type: application/json' -s http://localhost:8080/api/login -d '{"id": "fuzz"}' >/dev/null 2>&1
      cd schemathesis
      SCHEMATHESIS_HOOKS=hooks schemathesis run http://localhost:8080/api/docs/openapi.json
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
    (mkScript "mig" "sea-orm-cli migrate -d sea-migration generate $1")
    (mkScript "cov" "cargo llvm-cov nextest --no-fail-fast --all --ignore-filename-regex '(sea-entity|sea-migration).*\.rs' --color always --html --open")
    (mkScript "cov-ci" "cargo llvm-cov nextest --no-fail-fast --all --ignore-filename-regex '(sea-entity|sea-migration).*\.rs' --color always --codecov --output-path codecov.json")
    (mkScript "audit" "cargo audit --ignore RUSTSEC-2023-0071")

    (mkScript "ctest" "cargo nextest run --workspace --max-progress-running=1 \"$@\"")
    (mkScript "doc" "cargo run --bin api-doc > openapi.json")
  ];
in
  shellScripts
