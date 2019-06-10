Vault support
=============

Crate wrapped token
-------------------

```
# python3 create_wrapped_token.py -j $IAM_ACCESS_TOKEN -v $VAULT_URL --wrap-ttl $WRAPPED_TOKEN_DURATION --ttl $TOKEN_DURATION --period $RENEWED_TOKEN_DURATION
```

Read secret
-----------

```
# python3 read_secret_from_vault.py -v $VAULT_URL -j $IAM_ACCESS_TOKEN -p $READ_POLICY --secret-path $DESTINATION_PATH_ON_VAULT --key $KEY 
```

Write secret
------------

```
# python3 write_secret_to_vault.py -v $VAULT_URL -j $IAM_ACCESS_TOKEN -p $WRITE_POLICY --secret-path $DESTINATION_PATH_ON_VAULT --key $KEY --value $VALUE
```

Write secret using wrapped token
--------------------------------

```
# python3 write_secret_to_vault_using_wrapped_token.py -v $VAULT_URL -j $IAM_ACCESS_TOKEN -p $WRITE_POLICY --secret-path $DESTINATION_PATH_ON_VAULT --key $KEY --value $VALUE 
```

Delete secret
-------------

```
# python3 delete_secret_from_vault.py -v $VAULT_URL -j $IAM_ACCESS_TOKEN -p $DELETE_POLICY --secret-path$DESTINATION_PATH_ON_VAULT
```
