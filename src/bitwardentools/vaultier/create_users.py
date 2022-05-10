#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import json
import os
import re
import traceback
from collections import OrderedDict
from multiprocessing import Pool

import click

import bitwardentools as bwclient
from bitwardentools import Client, L, as_bool
from bitwardentools import crypto as bwcrypto
from bitwardentools import sanitize

bwclient.setup_logging()
JSON = os.environ.get("VAULTIER_JSON", "data/export/vaultier.json")
PASSWORDS = os.environ.get("VAULTIER_PASSWORDS", "data/export/vaultierpasswords.json")
BW_ORGA_NAME = os.environ.get("BW_ORGA_NAME", "bitwarden")
DONE = {"constructed": OrderedDict(), "errors": OrderedDict()}


class NameNotFound(RuntimeError):
    """."""


def record(client, email, secretd, constructed):
    try:
        user = client.get_user(email=email)
        if not user.emailVerified:
            user = client.validate(email)
        return user, secretd["password"]
    except bwclient.UserNotFoundError:
        pass
    try:
        return client.create_user(
            email, name=email.split("@")[0], password=secretd["password"]
        )
    except Exception as exc:
        trace = traceback.format_exc()
        print(trace)
        sid = email
        L.error(f"Error while creating {sid}\n{trace}")
        DONE["errors"][sid] = exc


@click.command()
@click.argument("jsonf", default=JSON)
@click.argument("passwordsf", default=PASSWORDS)
@click.argument("skippedusers", default="\\+.*@")
def main(jsonf, passwordsf, skippedusers):
    if skippedusers:
        skippedusers = re.compile(skippedusers, flags=re.I | re.M)
    L.info("start")
    client = Client()
    client.sync()
    vaultier_members = {}

    for jsonff in jsonf.split(":"):
        with open(jsonff) as fic:
            data = json.load(fic)
        # optim: load all secrets once
        for vdata in data["vaults"]:
            v = vdata["name"]
            for i in vdata["acls"]:
                vaultier_members.setdefault(i, {})
            for cdata in vdata["cards"]:
                c = cdata["name"]
                for i in cdata["acls"]:
                    vaultier_members.setdefault(i, {})
                n = sanitize(f"{v} {c}")
                for ix, secret in enumerate(cdata["secrets"]):
                    pass

    # unload skipped users
    for i in [a for a in vaultier_members]:
        if skippedusers and skippedusers.search(i):
            L.info(f"Skip {i}")
            vaultier_members.pop(i, None)

    # assign passwords
    if os.path.exists(passwordsf):
        with open(passwordsf, "r") as fic:
            passwords = json.loads(fic.read())
    else:
        passwords = {}

    for i, idata in vaultier_members.items():
        try:
            pw = passwords[i]
        except KeyError:
            pw = passwords[i] = bwcrypto.gen_password()
        vaultier_members[i]["password"] = pw

    with open(passwordsf, "w") as fic:
        json.dump(passwords, fic, indent=2, sort_keys=True)
    constructed = DONE["constructed"]
    # either create or edit passwords
    parallel = as_bool(os.environ.get("BW_PARALLEL_IMPORT", "1"))
    # parallel = False
    processes = int(os.environ.get("BW_PARALLEL_IMPORT_PROCESSES", "10"))
    items = []
    for n, secretd in vaultier_members.items():
        items.append((client, n, secretd, constructed))
    if parallel:
        with Pool(processes=processes) as pool:
            res = pool.starmap_async(record, items)
            res.wait()
            for ret in res.get():
                if not ret:
                    continue
                constructed[ret[0].id] = ret
    else:
        for n, secretd in vaultier_members.items():
            record(client, n, secretd, constructed)

    return constructed


if __name__ == "__main__":
    main()
# vim:set et sts=4 ts=4 tw=0:
