#!/usr/bin/env sh
set -ex
cd $(dirname $(readlink -f $0))
apk update && apk add openssl
openssl req -nodes -x509 -sha256 -newkey rsa:4096 \
  -keyout local/cert.key \
  -out local/cert.crt \
  -days 356 \
  -subj "/C=NL/ST=Zuid Holland/L=Rotterdam/O=ACME Corp/OU=IT Dept/CN=example.org"  \
  -addext "subjectAltName = DNS:localhost,DNS:wkbox2,DNS:localhost:3012,DNS:wkbox2:3012,DNS:vaultwarden:3011,DNS:vaultwarden:3012"
# vim:set et sts=4 ts=4 tw=80:
