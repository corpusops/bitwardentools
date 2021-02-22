# tools for working with bitwarden (_rs) and vaultier

This package containers a python3+ client for bitwarden which uses both a native python implementation but also wraps the official the official npm `@bitwarden/cli`.

The ultimate goal is certainly only to rely on python implementation against the bitwarden_rs server implementation.

## Features
- api controllable client
- Create, Read, Update, Delete,  on organizations, collection, ciphers, users (also disable/enable), and attachments
- Attach Ciphers to organization collections
- Donwload/Upload attachments to vault and organizations
- The client also integrate a thin wrapper to official npm CLI (see `call` mathod)
- Read [api](./src/bitwardentools/client.py)  for longer details
 
## install as a python lib
```bash
pip install bitwardentools
```

## Run in dev
### Configure
```bash
cp .env.dist .env
cp .env.local.dist .env.local
printf "USER_UID=$(id -u)\nUSER_GID=$(id -g)\n">>.env
```

### Build
```bash
eval $(egrep -hv '^#|^\s*$' .env .env.local|sed  -e "s/^/export /g"| sed -e "s/=/='/" -e "s/$/'/g"|xargs)
COMPOSE_FILE="docker-compose.yml:docker-compose-build.yml" docker-compose build
```

### Run

```bash
docker-compose run --rm app bash
```

```bash
sed "/COMPOSE_FILE/d" .env
echo COMPOSE_FILE=docker-compose.yml:docker-compose-dev.yml"
docker-compose up -d --force-recreate
docker-compose exec -U app bash
```

### run tests
```bash
sed "/COMPOSE_FILE/d" .env
echo COMPOSE_FILE=docker-compose.yml:docker-compose-dev.yml:docker-compose-test.yml"
docker-compose exec -U app app tox -e linting,coverage
```

## Credits and bibliography
- [gnunux](http://gnunux.info/) excellent articles:
    [1](http://gnunux.info/dotclear2/index.php?post/2020/10/11/%C3%89crire-un-client-Bitwarden-en-python-%3A-identifiant)
    [2](http://gnunux.info/dotclear2/index.php?post/2020/10/11/%C3%89crire-un-client-Bitwarden-en-python-%3A-cr%C3%A9er-une-organisation-et-une-collection)
    [3](http://gnunux.info/dotclear2/index.php?post/2020/10/11/%C3%89crire-un-client-Bitwarden-en-python)
- https://github.com/dani-garcia/bitwarden_rs/
- https://github.com/doy/rbw/tree/master/src
- https://github.com/bitwarden/jslib
- https://github.com/birlorg/bitwarden-cli/tree/trunk/python/bitwarden
- https://github.com/jcs/rubywarden


## Doc
see also [USAGE](./USAGE.md) (or read below on pypi)
