#!/bin/bash
set -x
docker-compose exec -T db bash -c \
    'printf "drop schema public cascade;create schema public;"|psql -U $POSTGRES_USER $POSTGRES_DB'
docker-compose stop -t0
docker-compose rm -f
docker-compose run --rm --entrypoint bash app -exc 'rm -rf /bitwarden/*'
docker-compose up -d --force-recreate --no-deps db setup bitwarden traefik
docker-compose up -d --force-recreate --no-deps app
