'''
  Import util function for easy access to vault 
'''
import requests

def getVaultSecrets(VAULT_ADDR, VAULT_SECRET_PATH, VAULT_TOKEN, VAULT_MOUNT):
    """
    Input: Take in Vault URL address, path to secrets, and user's token
    Output: Return dictoanry of secrets for the path provided
    """
    auth_header = {
        "X-Vault-Token": VAULT_TOKEN
    }
    url = f"{VAULT_ADDR}/v1/{VAULT_MOUNT}/data/{VAULT_SECRET_PATH}"
    response = requests.get(url=url, headers=auth_header)
    return response.json()['data']['data']