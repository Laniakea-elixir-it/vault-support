#!/usr/bin/env python
"""
"""

import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import argparse
import json

#______________________________________
def cli_options():
  parser = argparse.ArgumentParser(description='Vault connector')
  parser.add_argument('-i', '--iam-url', dest='iam_url', help='IAM endpoint')
  parser.add_argument('-d','--client-id',dest='iam_client_id',help='IAM Client ID')
  parser.add_argument('-s','--client-secret',dest='iam_client_secret',help='IAM Client Secret')
  parser.add_argument('-u','--username',dest='username',help='User Name')
  parser.add_argument('-p','--password',dest='password',help='User Password')
  parser.add_argument('-a','--audience', dest='audience', help='Bound Audience')
  return parser.parse_args()

#______________________________________
def get_iam_token():

  options = cli_options()

  data = { "client_id": options.iam_client_id,
           "client_secret": options.iam_client_secret,
           "grant_type": "password",
           "username": options.username,
           "password": options.password,
           "scope": "openid address phone profile offline_access email"
         }

  if options.audience:
    data["audience"]= options.audience

  iam_token_endpoint=options.iam_url+'/token'

  response = requests.post( iam_token_endpoint, params=data, verify=False )

  deserialized_response = json.loads(response.text)

  print(deserialized_response['access_token'])

#______________________________________
if __name__ == '__main__':
  get_iam_token()
