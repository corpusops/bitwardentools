## migrate

```sh
VAULTIER_KEY=$(echo $(cat ~/vaultier_key.bin |base64)|sed "s/ //g")
cat >>.env << EOF
VAULTIER_KEY=${VAULTIER_KEY}
# if your vauiltier has aditionnal httpauth
# VAULTIER_HTTP_PASSWORD=htpasswd
# VAULTIER_HTTP_USER=user
VAULTIER_EMAIL=myvaultier.email@d.com
VAULTIER_URL=https://vaultier.foo.net
VAULTIER_JSON=data/export/vaultierfile.json
BW_ORGA_NAME=MyBitwardenOrga
BITWARDEN_PW=MasterPassword
BITWARDEN_SERVER=https://bitwd.foo.net
BITWARDEN_EMAIL=foo@foo.com
```

## Export vaultier data
- It will produce data/export/vaultname.json
- And download attachments inside data/export/secret$id/

```sh
time python src/bitwardentools/vaultier/export.py
```

## import structure
As bitwarden has only 2 folds, where vaultier has 3, cards are migrated into bitwarden and named `$vault $card`; this is the link between the two systems, please do not rename your card as long as you want to continue to migrate or it will duplicate things.
```sh
time python src/bitwardentools/vaultier/import_structure.py
```

## sync secrets
```sh
time python src/bitwardentools/vaultier/sync_secrets.py
```
