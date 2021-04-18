#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import json
import os
from collections import OrderedDict
from multiprocessing import Pool

import click

import bitwardentools
from bitwardentools import Client, L, as_bool
from bitwardentools import client as bwclient
from bitwardentools import sanitize

bitwardentools.setup_logging()
JSON = os.environ.get("VAULTIER_JSON", "data/export/vaultier.json")


@click.command()
@click.argument("jsonf", default=JSON)
@click.option("--server", default=bitwardentools.SERVER)
@click.option("--email", default=bitwardentools.EMAIL)
@click.option("--password", default=bitwardentools.PASSWORD)
def main(jsonf, server, email, password):
    L.info("start")
    client = Client(server, email, password)
    client.api_sync()
    orgas_to_import = OrderedDict()
    for jsonff in jsonf.split(":"):
        with open(jsonff) as fic:
            data = json.load(fic)
        for vi, vdata in enumerate(data["vaults"]):
            v = sanitize(vdata["name"])
            if not vdata["cards"]:
                L.info(f"Skipping {v} as it has no cards")
                continue
            orga = {"bw": None, "vault": vdata, "name": v, "collections": OrderedDict()}
            try:
                orgas_to_import[v]
            except KeyError:
                try:
                    orga["bw"] = client.get_organization(v)
                    L.info(f"Already created orga {v}")
                except bwclient.OrganizationNotFound:
                    L.info(f"Will create orga: {v}")
            orgas_to_import[v] = orga
            for cdata in vdata["cards"]:
                c = sanitize(cdata["name"])
                try:
                    orga["collection_name"]
                except KeyError:
                    orga["collection_name"] = c
                    L.info(f"{c} is Default Collection")
                    continue
                try:
                    if not orga["bw"]:
                        raise KeyError()
                    client.get_collection(c, orga=orga["bw"])
                    L.info(f"Already created {c}")
                except (bwclient.CollectionNotFound, KeyError):
                    try:
                        orga["collections"][c]
                    except KeyError:
                        L.info(f"Will create {c} in orga: {v}")
                        orga["collections"][c] = {"card": cdata, "name": c}
            orga.setdefault("collection_name", v)

    constructed = OrderedDict()
    parallel = as_bool(os.environ.get("BW_PARALLEL_IMPORT", "1"))
    processes = int(os.environ.get("BW_PARALLEL_IMPORT_PROCESSES", "100"))

    # create orgas
    items = []
    for org, odata in orgas_to_import.items():
        if odata["bw"] is None:
            items.append([client, org, odata, email, constructed])
    if parallel:
        with Pool(processes=processes) as pool:
            res = pool.starmap_async(record_orga, items)
            res.wait()
            for ret in res.get():
                if not ret:
                    continue
                org, orga = ret
                orgas_to_import[org]["bw"] = constructed[orga.id] = orga

    else:
        for item in items:
            ret = record_orga(*item)
            org, orga = ret
            orgas_to_import[org]["bw"] = constructed[orga.id] = orga

    client.refresh()

    # create collections
    items = []
    for i, o in orgas_to_import.items():
        for col, c in o["collections"].items():
            items.append([client, i, o["bw"].id, col, c["card"]["id"], constructed])
    if parallel:
        with Pool(processes=processes) as pool:
            res = pool.starmap_async(record, items)
            res.wait()
            for ret in res.get():
                if not ret:
                    continue
                constructed[ret.id] = ret
    else:
        for item in items:
            record(*item)


def record_orga(client, org, odata, email, constructed):
    if odata["bw"] is None:
        ret = client.create(
            **{
                "object": "organization",
                "name": org,
                "collection_name": odata["collection_name"],
                "email": email,
            }
        )
        odata["bw"] = ret
    return org, odata["bw"]


def record(client, i, oid, col, c, constructed):
    payload = {
        "externalId": c,
        "object": "org-collection",
        "name": col,
        "organizationId": oid,
    }
    ret = client.create(**payload)
    return ret


if __name__ == "__main__":
    main()
# vim:set et sts=4 ts=4 tw=120:
