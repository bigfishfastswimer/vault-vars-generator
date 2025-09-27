# Vault Secret Fetcher

This utility reads a `vault_secrets.yaml` file, validates the schema, and fetches secrets from HashiCorp Vault using the official Go SDK. The resulting passwords are written to `vault/vault_received.yaml` in the format `name=password` under the `vault` key.

## Configuration

The configuration file must contain a `vault_secrets` array. Each entry describes the Vault location to read:

```yaml
vault_secrets:
  - name: artifactoryPassword
    default:
      vault:
        account_id: GA00016094
        namespace: APS00376-non
  - name: iiq_console_password
    default:
      vault:
        account_id: GA03000912
        namespace: AP668493612630IG-NON
    branch-overrides:
      - name: iiq-develop
        vault:
          account_id: GA00300812
          namespace: AP6649361230IG-NON
```

* `name` – identifier for the secret in the output file.
* `default.vault.account_id` – CyberArk account ID (used to build the Vault path `cyberark/accounts/<account_id>`).
* `default.vault.namespace` – Vault namespace for the default lookup.
* `branch-overrides` – optional overrides keyed by branch name. If the supplied branch (from the `--branch` flag or detected Bamboo environment variables) matches one of these entries, its `vault` block is used instead of the default.

The loader validates that each secret has a unique `name` and that every target includes both an `account_id` and `namespace`.

## Usage

Set the required Vault environment variables and execute the binary:

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=...

cd vaultfetcher
GOFLAGS=-mod=mod go run ./cmd/vaultfetcher \
  --config path/to/vault_secrets.yaml \
  --branch "$BAMBOO_PLAN_REPOSITORY_BRANCH" \
  --output vault/vault_received.yaml
```

Flags:

* `--config` – path to the YAML file (default `vault_secrets.yaml`).
* `--branch` – branch name for override resolution. If omitted, the program inspects Bamboo variables such as `BAMBOO_PLAN_REPOSITORY_BRANCH`.
* `--output` – destination for the rendered YAML (default `vault/vault_received.yaml`).
* `--mount` – KV v2 mount path (default `secrets/sync`).
* `--password-field` – key in the Vault secret that contains the password (default `password`).
* `--vault-addr` – override for the Vault address (falls back to `VAULT_ADDR`).
* `--timeout` – request timeout per secret (default 30s).

The output file contains a `vault` array with `name=password` strings that Bamboo can consume.

## Notes

* The program uses the official Vault Go SDK (`github.com/hashicorp/vault/api`) and expects KV v2 semantics at the provided mount path.
* Namespace support is handled by creating a client per secret and calling `SetNamespace` before each request.
* When running in environments without network access, `go mod tidy` may fail to download module dependencies. In such cases, run the command on a machine with access to populate `go.sum` before compiling.
