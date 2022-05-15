#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import json
import os

import click

import bitwardentools
from bitwardentools import MAIL_LANG, L, as_bool, notify_access
from bitwardentools.vaultier import PASSWORDS

bitwardentools.setup_logging()
JSON = os.environ.get("VAULTIER_JSON", "data/export/vaultier.json")


@click.command()
@click.option("--server", default=bitwardentools.SERVER)
@click.argument("passwordsf", default=PASSWORDS)
@click.option("--mail-lang", default=MAIL_LANG)
@click.option("--tls", default=os.environ.get("BW_MAIL_TLS", "1"))
@click.option("--dry-run", default=os.environ.get("BW_DRYRUN", "1"))
@click.option("--mail-server", default=os.environ.get("BW_MAIL_SERVER", "localhost"))
@click.option("--mail-port", default=os.environ.get("BW_MAIL_PORT", "25"))
@click.option("--mail-login", default=os.environ.get("BW_MAIL_LOGIN", ""))
@click.option("--mail-from", default=os.environ.get("BW_MAIL_FROM", ""))
@click.option("--mail-pw", default=os.environ.get("BW_MAIL_PW", ""))
def main(
    server,
    passwordsf,
    mail_lang,
    tls,
    dry_run,
    mail_server,
    mail_port,
    mail_login,
    mail_from,
    mail_pw,
):
    tls = as_bool(tls)
    dry_run = as_bool(dry_run)
    if not mail_from:
        mail_from = mail_login
    assert mail_login
    assert mail_pw
    L.info("start")
    with open(passwordsf, "r") as fic:
        passwords = json.loads(fic.read())
    for login, password in passwords.items():
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
