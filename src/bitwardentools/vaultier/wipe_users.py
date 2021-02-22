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

bwclient.setup_logging()
JSON = os.environ.get("VAULTIER_JSON", "data/export/vaultier.json")
PASSWORDS = os.environ.get("VAULTIER_PASSWORDS", "data/export/vaultierpasswords.json")
BW_ORGA_NAME = os.environ.get("BW_ORGA_NAME", "bitwarden")
DONE = {"constructed": OrderedDict(), "errors": OrderedDict()}


class NameNotFound(RuntimeError):
    """."""


def record(client, email, secretd, constructed):
    try:
        return client.delete_user(email)
    except bwclient.UserNotFoundError:
        pass
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

    with open(passwordsf, "r") as fic:
        passwords = json.load(fic)

    constructed = DONE["constructed"]
    # either create or edit passwords
    parallel = as_bool(os.environ.get("BW_PARALLEL_IMPORT", "1"))
    # parallel = False
    processes = int(os.environ.get("BW_PARALLEL_IMPORT_PROCESSES", "10"))
    items = []
    for n, secretd in passwords.items():
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
        for n, secretd in passwords.items():
            record(client, n, secretd, constructed)

    return constructed


if __name__ == "__main__":
    main()
# vim:set et sts=4 ts=4 tw=0:
