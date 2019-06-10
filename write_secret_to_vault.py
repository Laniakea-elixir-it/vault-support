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
  parser.add_argument('-s', '--secret-path', dest='secret_path', help='Secret path on vault')
  parser.add_argument('--ttl', dest='token_time_duration',  default='1h',help='Vault Token time duration')
  parser.add_argument('--period', dest='renewal_time_duration',  default='1h',help='Vault Token renewal time duration')
  parser.add_argument('--key', dest='user_key', default='luks', help='Vault user key value, i.e. passphrase')
  parser.add_argument('--value', dest='user_value', help='Vault user key')
  return parser.parse_args()

#______________________________________
def parse_response(response):

  if not response["data"]["created_time"]:
    raise Exception("No cretation time")

  if response["data"]["destroyed"] != False:
    raise Exception("Token already detroyed")

  if response["data"]["version"] != 1:
    raise Exception("Token not at 1st verion")

  if response["data"]["deletion_time"] != "":
    raise Exception("Token aready deleted")

  return 0

#______________________________________
def write_secret_to_vault():

  options = cli_options()

  vault = VaultIntegration( options.vault_url, options.jwt_token, "secrets" )

  auth_token = vault.get_auth_token()

  write_token = vault.get_token( auth_token, options.vault_policy, options.token_time_duration, options.renewal_time_duration)

  response_output = vault.write_secret( write_token, options.secret_path, options.user_value, options.user_key)

  parse_response(response_output)


#______________________________________
if __name__ == '__main__':
  write_secret_to_vault()
