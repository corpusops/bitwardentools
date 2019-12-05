#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import datetime
import enum
import logging
import os
import re
import smtplib
from email.mime.text import MIMEText
from http.client import HTTPConnection


class VAULTIER_SECRET(enum.IntEnum):
    secret = 200
    note = 100
    file = 300


def sanitize(st):
    return st


def as_bool(value):
    if isinstance(value, str):
        return bool(re.match("^(y|o|1|t)", value.lower()))
    else:
        return bool(value)


CFG = os.environ.get("CONFIG", "/w/data/config.init")
EXPORT_DIR = os.environ.get("VAULTIER_EXPORT_DIR", "/w/data/export")
L = logging.getLogger("passwords")
LOGLEVEL = os.environ.get("LOGLEVEL", "info").upper()
REQUEST_DEBUG = as_bool(os.environ.get("REQUEST_DEBUG", ""))
_vars = {"debug": False}
MAIL_LANG = os.environ.get("MAILLANG", "fr")
MAIL_TEMPLATES = {
    "subject": {
        "en": "Your bitwarden access ({server})",
        "fr": "Votre accès bitwarden ({server})",
    },
    "mail": {
        "en": """\
Hi,

You can connect to {server}

    login: {login}
    password: {password}

Thx to reinit your password upon first connection

Thx,

Bitwarden team
""",
        "fr": """\
Bonjour,

Vous pouvez vous connecter à {server}

    login: {login}
    password: {password}

Merci de réinitialiser votre mot de passe à la première connexion.

Cordialement,

Équipe bitwarden
""",
    },
}


def notify_access(
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
):
    subject = f"Your bitwarden {server} access"
    infos = dict(
        server=server,
        login=login,
        password=password,
    )
    text = MAIL_TEMPLATES["mail"][mail_lang].format(**infos)
    subject = MAIL_TEMPLATES["subject"][mail_lang].format(**infos)
    msg = MIMEText(text)
    date = datetime.datetime.now().strftime("%d/%m/%Y %H:%M +0000")
    msg["From"] = mail_from
    msg["To"] = login
    msg["Date"] = date
    msg["Subject"] = subject
    if dry_run:
        L.info(f"Would send {mail_from} -> {login}")
        L.info(msg.as_string())
        L.info(f"\n\n-- PLAINTEXT --:\n{text}")
    else:
        s = smtplib.SMTP(mail_server, int(mail_port))
        s.set_debuglevel(1)
        if tls:
            s.starttls()
        if login:
            s.login(mail_login, mail_pw)
        s.sendmail(mail_from, [login], msg.as_string())
        s.quit()
    return msg


def toggle_debug(activate=None, debuglevel=logging.DEBUG, errorlevel=logging.INFO):
    if activate is None:
        activate = not _vars["debug"]
    dl = debuglevel <= logging.DEBUG and 1 or 0
    lvl = activate and debuglevel or errorlevel
    HTTPConnection.debuglevel = dl
    req_log = logging.getLogger("requests.packages.urllib3")
    req_log.setLevel(lvl)
    req_log.propagate = activate
    _vars["debug"] = activate
    logging.getLogger("").setLevel(lvl)
    return activate


def setup_logging(loglevel=LOGLEVEL):
    logging.basicConfig(level=getattr(logging, loglevel))
    debuglvl = REQUEST_DEBUG and logging.DEBUG or logging.INFO
    toggle_debug(True, debuglevel=debuglvl)


def lowered_value(i):
    return isinstance(i, str) and i.lower() or i


def caseinsentive_key_search(d, k):
    lk = lowered_value(k)
    for i in d:
        li = lowered_value(i)
        if li == lk:
            return d[i]
    raise KeyError(k)


# vim:set et sts=4 ts=4 tw=0:
