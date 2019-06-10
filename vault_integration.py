#!/usr/bin/env python
"""
Hashicorp Vault management class
Currently supported kv secrets engine - version 2 (https://www.vaultproject.io/api/secret/kv/kv-v2.html#delete-metadata-and-all-versions)
and jwt auth method (https://www.vaultproject.io/docs/auth/jwt.html)
"""

# Imports
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import json

class VaultIntegration:
  def __init__(self, vault_url, jwt_token, secrets_root):
    """
    Constructor require vault endpoint, a vaild jwt token and the secrets root path.
    """

    self.vault_url = vault_url
    self.secrets_root = secrets_root

    login_url = self.vault_url + '/v1/auth/jwt/login'

    data = '{ "jwt": "'+ jwt_token +  '" }'

    response = requests.post(login_url, data=data, verify=False)

    deserialized_response = json.loads(response.text)

    self.vault_auth_token = deserialized_response["auth"]["client_token"]

  #______________________________________
  def get_auth_token(self): return self.vault_auth_token

  #______________________________________
  def get_wrapped_token(self, wrap_ttl, auth_token, policy, ttl, period):
    """
    Get Vault wrapped token with specific policy
    """

    create_url = self.vault_url + '/v1/auth/token/create'

    headers = {
               "X-Vault-Wrap-TTL": wrap_ttl,
               "X-Vault-Token": auth_token
              }

    data = '{ "policies": ["'+policy+'"], "ttl": "'+ttl+'", "period": "'+period+'" }'

    response = requests.post(create_url, headers=headers, data=data, verify=False)

    deserialized_response = json.loads(response.text)

    return deserialized_response["wrap_info"]["token"]

  #______________________________________
  def get_token(self, auth_token, policy, ttl, period):
    """
    Get Vault token with specific policy
    """

    create_url = self.vault_url + '/v1/auth/token/create'

    headers = {
               "X-Vault-Token": auth_token
              }

    data = '{ "policies": ["'+policy+'"], "ttl": "'+ttl+'", "period": "'+period+'" }'

    response = requests.post(create_url, headers=headers, data=data, verify=False)

    deserialized_response = json.loads(response.text)

    return deserialized_response["auth"]["client_token"]

  #______________________________________
  def write_secret(self, token, secret_path, key, value):
    """
    Write Secret to Vault
    """

    write_url = self.vault_url + '/v1/'+self.secrets_root+'/data/' + secret_path

    headers = {
               "X-Vault-Token": token
              }

    data = '{ "options": { "cas": 0 }, "data": { "'+key+'": "'+value+'"} }'

    response = requests.post(write_url, headers=headers, data=data, verify=False)

    deserialized_response = json.loads(response.text)

    try:
      deserialized_response["data"]
    except KeyError:
      raise Exception("[FATAL] Unable to write vault path.")

    return deserialized_response


  #______________________________________
  def read_secret(self, token, secret_path, key):
    """
    Read Secret from Vault.
    """

    read_url = self.vault_url + '/v1/'+self.secrets_root+'/data/' + secret_path

    headers = {
               "X-Vault-Token": token
              }

    response = requests.get( read_url, headers=headers, verify=False )

    deserialized_response = json.loads(response.text)

    try:
      deserialized_response["data"]
    except KeyError:
      raise Exception("[FATAL] Unable to read vault path.")

    return deserialized_response["data"]["data"][key]

  #______________________________________
  def delete_secret(self, token, secret_path):
    """
    Permanently delete secret and metadata from Vault.
    """

    delete_url = self.vault_url + '/v1/'+self.secrets_root+'/metadata/' + secret_path

    headers = {
               "X-Vault-Token": token
              }

    response = requests.delete(delete_url, headers=headers, verify=False)

  #______________________________________
  def revoke_token(self, token):
    """
    Revoke (self) token
    """

    revoke_url = self.vault_url + '/v1/auth/token/revoke-self'

    headers = {
               "X-Vault-Token": token
              }

    response = requests.post( revoke_url, headers=headers, verify=False )
