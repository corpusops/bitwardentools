#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import json
import os
import secrets

import click

import bitwardentools
from bitwardentools import MAIL_LANG, Client, L, as_bool
from bitwardentools import client as bwclient
from bitwardentools import notify_access

bitwardentools.setup_logging()
PASSWORDS = os.environ.get("BW_PASSWORDS_JSON", "data/passwords.json")


@click.command()
@click.option("--login")
@click.option("--password", default="")
@click.option(
    "--register-to", default=os.environ.get("BW_ORGAS_REGISTER_TO", "").split(":")
)
@click.option("--server", default=bitwardentools.SERVER)
@click.option("--mail-lang", default=MAIL_LANG)
@click.option("--tls", default=os.environ.get("BW_MAIL_TLS", "1"))
@click.option("--dry-run", default=os.environ.get("BW_DRYRUN", "1"))
@click.option("--mail-server", default=os.environ.get("BW_MAIL_SERVER", "localhost"))
@click.option("--mail-port", default=os.environ.get("BW_MAIL_PORT", "25"))
@click.option("--mail-login", default=os.environ.get("BW_MAIL_LOGIN", ""))
@click.option("--mail-from", default=os.environ.get("BW_MAIL_FROM", ""))
@click.option("--mail-pw", default=os.environ.get("BW_MAIL_PW", ""))
@click.option("--notify", default=os.environ.get("BW_MAIL_NOTIFY", "1"))
@click.argument("passwordsf", default=PASSWORDS)
def main(
    login,
    password,
    register_to,
    server,
    mail_lang,
    tls,
    dry_run,
    mail_server,
    mail_port,
    mail_login,
    mail_from,
    mail_pw,
    notify,
    passwordsf,
):
    tls = as_bool(tls)
    dry_run = as_bool(dry_run)
    notify = as_bool(notify)
    passwords = {}
    if not os.path.exists(passwordsf):
        with open(passwordsf, "w") as fic:
            fic.write("{}")
    with open(passwordsf) as fic:
        passwords = json.load(fic)
    try:
        password = passwords[login]
    except KeyError:
        try:
            assert password
        except AssertionError:
            password = secrets.token_hex(32)
    write = passwords.get(login, "") != password
    passwords[login] = password
    if write:
        with open(passwordsf, "w") as fic:
            json.dump(passwords, fic, indent=2, sort_keys=True)

    if not mail_from:
        mail_from = mail_login
    assert login
    assert password
    assert mail_login
    assert mail_pw
    L.info("start")
    client = Client()
    client.sync()

    try:
        user = client.get_user(email=login)
        if not user.emailVerified:
            user = client.validate(login)
    except bwclient.UserNotFoundError:
        client.create_user(
            login, name=login.split("@")[0], password=password, auto_validate=True
        )
    for i in register_to:
        client.set_organization_access(
            login, i, access_level=bwclient.CollectionAccess.admin, accessAll=True
        )
        try:
            client.accept_invitation(i, login)
        except bwclient.AlreadyInvitedError:
            pass
        try:
            client.confirm_invitation(i, login)
        except bwclient.AlreadyConfirmedError:
            pass
    if notify:
        notify_access(
            login,
            password,
            server,
            mail_lang,
            tls,
            dry_run,
            mail_server,
            mail_port,
            mail_login,
            mail_from,
            mail_pw,
        )


if __name__ == "__main__":
    main()
#
