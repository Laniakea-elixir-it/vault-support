#!/usr/bin/env python
"""
"""

import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import argparse
import json


from vault_integration import VaultIntegration

logfile = '/tmp/readdb.log'

#______________________________________
def cli_options():
  parser = argparse.ArgumentParser(description='Vault connector')
  parser.add_argument('-v', '--vault-url', dest='vault_url', help='Vault endpoint')
  parser.add_argument('-j', '--jwt-token', dest='jwt_token', help='JWT Token')
  parser.add_argument('-p', '--policy', dest='vault_policy', default="delete_only", help='Vault Policy')
  parser.add_argument('-s', '--secret-path', dest='secret_path', help='Vault secret path to delete')
  parser.add_argument('--ttl', dest='token_time_duration',  default='1h',help='Vault Token time duration')
  parser.add_argument('--period', dest='renewal_time_duration',  default='1h',help='Vault Token renewal time duration')
  return parser.parse_args()

#______________________________________
def delete_secret_from_vault():

  options = cli_options()

  vault = VaultIntegration( options.vault_url, options.jwt_token, "secrets" )

  auth_token = vault.get_auth_token()

  delete_token = vault.get_token( auth_token, options.vault_policy, options.token_time_duration, options.renewal_time_duration)

  vault.delete_secret( delete_token, options.secret_path  )

#______________________________________
if __name__ == '__main__':
  delete_secret_from_vault()
