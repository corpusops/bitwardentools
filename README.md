tools for working with bitwarden (_rs) and vaultier
===================================================

This package containers a python3+ client for bitwarden which uses both a native python implementation but also wraps the official the official npm `@bitwarden/cli`.

The ultimate goal is certainly only to rely on python implementation against the bitwarden_rs server implementation.


configure
------------
```bash
cp .env.dist .env
cp .env.local.dist .env.local
printf "USER_UID=$(id -u)\nUSER_GID=$(id -g)\n">>.env
```

build
---------
```bash
eval $(egrep -hv '^#|^\s*$' .env .env.local|sed  -e "s/^/export /g"| sed -e "s/=/='/" -e "s/$/'/g"|xargs)
COMPOSE_FILE="docker-compose.yml:docker-compose-build.yml" docker-compose build
```

run in dev
---------------
```bash
docker-compose run --rm app bash
```

In dev, with scripts mounted as volumes
```bash
COMPOSE_FILE="docker-compose.yml:docker-compose-dev.yml" docker-compose run --rm app bash
```

see also [use](./use.md)

install as a python lib
---------------------------
```bash
pip install bitwardentools
```

Features
-----------
- api controllable client
- Create, Read, Update, Delete,  on organizations, collection, ciphers, users (also disable/enable), and attachments
- Attach Ciphers to organization collections
- Donwload/Upload attachments to vault and organizations
- The client also integrate a thin wrapper to official npm CLI (see `call` mathod)
- Read [api](./src/bitwardentools/client.py)  for longer details


```python
client = Client(server, email, password)
client.sync()
#
# direct object creation methods
# organization
client.create_organization('foo', 'foo@foo.com')ote
# collection
client.create_collection('bar', orga='foo')
# default item/login
payload = {
    "notes": "supernote",
    "login": {
        "totp": "aze",
        'username': "alice", "password": "rabbit",
        "uris": [{"match": None, "uri": "http://a"}]
    }
}
client.create_item("sec5", orga, collections=[col], **payload)
# if orga is None cipher will go inside user vault
client.create_item("secpersonal", **payload)
## is a synoym: client.create_login
# identity
# title": "Mr/Mrs/Ms/Dr"
payload = {
    "identity": {
        "address1": "foo", "address2": "foo", "address3": "foo", "city": "foo", "postalCode": "foo",
        "country": "foo", "state": "foo", "username": "foo", "company": "foo",
        "phone": "foo", "email": "foo",
        "title": "Mrs", "firstName": "foo", "lastName": "foo", "middleName": "foo",
        "ssn": "foo", "licenseNumber": "foo", "passportNumber": "foo",
    },
    "notes": "foo",
}
client.create_identity("sec1", orga, collections=[col], **payload)
# note
payload = {
    "fields": [{"name": "thisisabool", "type": 2, "value": False}],
    "notes": "notenote",
    "secureNote": {"type": 0},
}
client.create_securenote("sec2", orga, collections=[col], **payload)
# card
payload = {
    "card": {"brand": "sec", "cardholderName": "foo",
             "number": "aaa", "code": "123456",
             "expMonth": "10", "expYear": "2013"},
    "fields": [{"name": "aaa", "type": 0, "value": "aaa"}],
    "notes": "aaa"
}
client.create_card("sec4", orga, collections=[col], **payload)
#
# create only with json payloads
orga = client.create(**{
    'object': 'organization',
    'name': "org",
    'email': email})
col = client.create(**{
    'object': 'org-collection',
    'name': "testcol",
    'organizationId': client.item_or_id(orga)})
col2 = client.create(**{
    'object': 'org-collection',
    'name': "testcol2",
    'organizationId': client.item_or_id(orga)})
cipher = client.create(**{
    "name": "test",
    "object": "item",
    "organizationId": orga.id,
    "notes": "supernote",
    "login": {'username': "alice", "password": "rabbit"}})
#
# Patch existing objects
testorg = client.get_organization("org")
client.edit_organization(testorg, name='fooorg')
#
testcol = client.get_collection("testcol")
client.edit_orgcollection(testcol, name='foocol')
#
# Play with ciphers
all_ciphers = client.get_ciphers()
cipher = client.get_cipher("test", collection=col, orga=orga)
# Put cipther in collection col2
client.link(cipher, col2)
#
# Attachments
client.attach(sec, "/path/to/foo.zip")
# reload cipher with it's new attachment
# default dir in current working directory, default filename is uploaded filename
client.download(sec.attachments[0],
                directory='/w/data/titi/toto',
                filename='tata.zip')
client.delete_attachments(sec)
#
# users management
#
users = client.get_users()  # > {"emails": {}, "ids": {}, "names": {}} users indexed dicts
# search one user
user = client.get_user(email="foo@bar.com")
user = client.get_user(name="foo")
user = client.get_user(id="424242424-4242-4242-4242-424242424242")
# enable/delete/disable methods can take id/email/name or user instances as kwargs:
client.disable_user(email="foo@bar.com")
client.disable_user(id="424242424-4242-4242-4242-424242424242")
client.disable_user(name="foo")
client.disable_user(user=user)
# other methods
client.enable_user(user=/name=/id=/email=)
client.delete_user(user=/name=/id=/email=)
# if not password, it will be autogenerated and in the return tuple
user, pw = client.create_user('foo@bar.com', password=, passwordhint=, name=)
# If you use bitwarden_rs and you setted up the bitwarden rs key,
# the user will be automatically validated
# you can manually validate an account with:
user = client.validate('foo@bar.com')
```

encode the bitwarden_rs key for autovalidating user
-------------------------------------------------------
```sh
cat $BITWARDEN_RS_SERVER_DATA/rsa_key.der|base64|xargs -n1 printf;echo
=> copy paste the result in your .env.local this way
BITWARDEN_PRIVATE_KEY=MIIxxx
```

vaultier export /bitwarden import notes
----------------------------------------
import must be done this ways

```python
# export vaultier data to json file for cards and files for attachments
python src/bitwardentools/vaultier/export.py
# load vaultier json serialized vaults/cards into bitwarden orga/collections
python src/bitwardentools/vaultier/import_structure.py
# load vaultier json secrets into bitwarden ciphers
python src/bitwardentools/vaultier/sync_secrets.py
# load vaultier json members as bitwarden users Profiles
python src/bitwardentools/vaultier/invite.py
# link users to their relative orga/collections as on vaultier
python src/bitwardentools/vaultier/acls.py
```


Credits and bibliography
-------------------------
- [gnunux](http://gnunux.info/) excellent articles:
    [1](http://gnunux.info/dotclear2/index.php?post/2020/10/11/%C3%89crire-un-client-Bitwarden-en-python-%3A-identifiant)
    [2](http://gnunux.info/dotclear2/index.php?post/2020/10/11/%C3%89crire-un-client-Bitwarden-en-python-%3A-cr%C3%A9er-une-organisation-et-une-collection)
    [3](http://gnunux.info/dotclear2/index.php?post/2020/10/11/%C3%89crire-un-client-Bitwarden-en-python)
- https://github.com/dani-garcia/bitwarden_rs/
- https://github.com/doy/rbw/tree/master/src
- https://github.com/bitwarden/jslib
- https://github.com/birlorg/bitwarden-cli/tree/trunk/python/bitwarden
- https://github.com/jcs/rubywarden

