import requests
import json

def get_vault_secrets(vault_address, vault_secret_path, vault_mount):
    vault_token = get_token()
    auth_header = {"X-Vault-Token": vault_token}
    url = f"{vault_address}/v1/{vault_mount}/data/{vault_secret_path}"
    response = requests.get(url=url, headers=auth_header)
    return response.json()["data"]["data"]


def get_token():
    with open("/vault/secrets/vault_config.json", "r", encoding="utf-8") as file:
        token = json.load(file)

    return token["token"]