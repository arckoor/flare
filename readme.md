[![CI](https://github.com/arckoor/flare/actions/workflows/ci.yml/badge.svg)](https://github.com/arckoor/flare/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/arckoor/flare/graph/badge.svg?token=1D279OLONO)](https://codecov.io/gh/arckoor/flare)

# flare

Create polls for images.

## Development
Using the [nix](https://nixos.org/download/) package manager is recommended.
The provided [flake.nix](/flake.nix) sets up all necessary development dependencies, as well as providing a few utility commands.
You can use [nix-direnv](https://github.com/nix-community/nix-direnv), or use `nix develop` directly. Use `start-db` and `stop-db` to manage the databases.
If you are not using nix, you will need a `postgres` and a `valkey` instance.
For configuration options of those services, see the flake.nix file.

### Setup
Copy [config.example.toml](/server/config.example.toml) and rename it to `config.toml`.
Some entries already have sane defaults, others you will have to configure yourself.
Cryptographically strong KEKs for the JWT implementation can be generated using `botan rng --format=hex 64`.

#### Certificates and mTLS
flare uses mTLS between itself and the exposing reverse proxy.
Certificates can be generated using the [cert-gen.sh](/cert-gen/cert-gen.sh) file.
Any reverse proxy (e.g. caddy) can be used for development work, or you can disable mTLS entirely.

#### OAuth Providers
flare uses a number of oauth providers, for which you need to acquire client IDs / secrets.

##### Discord
A new application can be created at the [Discord Developer Portal](https://discord.com/developers/applications).
In the OAuth2 tab, add your callback URL (e.g. `https://localhost/api/oauth/discord/callback`).
This is also were you will find your client id and secret.

##### GitHub
A new application can be created in the [GitHub settings](https://github.com/settings/developers).
Set your callback URL (e.g.`https://localhost/api/oauth/github/callback`).
After creating an app, you will be shown your client id and secret.

### Adding to the database schema
All schema entries are migration-first.
If you need to modify the schema, create a new migration with your changes.
If the latest migration has not been part of a release, it should be modified instead of creating a new migration.
Afterwards run any test, it does not need to succeed, only the migration must be successful.
Afterwards run the `gen` command in the `server/` directory.
