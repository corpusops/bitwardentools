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
from bitwardentools.vaultier import AS_SINGLE_ORG

bitwardentools.setup_logging()
JSON = os.environ.get("VAULTIER_JSON", "data/export/vaultier.json")


@click.command()
@click.argument("jsonf", default=JSON)
@click.option("--server", default=bitwardentools.SERVER)
@click.option("--email", default=bitwardentools.EMAIL)
@click.option("--password", default=bitwardentools.PASSWORD)
@click.option("--assingleorg", " /-S", default=AS_SINGLE_ORG, is_flag=True)
def main(jsonf, server, email, password, assingleorg):
    L.info("start")
    client = Client(server, email, password)
    client.api_sync()
    orgas_to_import = OrderedDict()
    for jsonff in jsonf.split(":"):
        with open(jsonff) as fic:
            data = json.load(fic)
        orga = {}
        if assingleorg:
            organ = data["name"]
            try:
                orgao = client.get_organization(organ)
                L.info(f"Already created orga {organ}")
            except bwclient.OrganizationNotFound:
                orgao = None
                L.info(f"Will create orga: {organ}")
        for vi, vdata in enumerate(data["vaults"]):
            v = sanitize(vdata["name"])
            if not vdata["cards"]:
                L.info(f"Skipping {v} as it has no cards")
                continue
            if not assingleorg:
                orga = {}
                organ = v
                try:
                    orgas_to_import[organ.lower()]
                except KeyError:
                    try:
                        orgao = client.get_organization(v)
                        L.info(f"Already created orga {v}")
                    except bwclient.OrganizationNotFound:
                        orgao = None
                        L.info(f"Will create orga: {v}")
            orga.update({"bw": orgao, "name": organ})
            orga.setdefault("collections", OrderedDict())
            orgas_to_import.setdefault(organ.lower(), orga)
            for cdata in vdata["cards"]:
                cn = sanitize(cdata["name"])
                vc = cn
                if assingleorg:
                    vc = f"{v} {cn}"
                try:
                    orga["collection_name"]
                except KeyError:
                    orga["collection_name"] = vc
                    L.info(f"{vc} is Default Collection")
                    continue
                try:
                    if not orga["bw"]:
                        raise KeyError()
                    client.get_collection(vc, orga=orga["bw"])
                    L.info(f"Already created {vc}")
                except (bwclient.CollectionNotFound, KeyError):
                    try:
                        orga["collections"][vc.lower()]
                    except KeyError:
                        L.info(f"Will create {vc} in orga: {v}")
                        orga["collections"][vc.lower()] = {"card": cdata, "name": vc}
            orga.setdefault("collection_name", vc)

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
            items.append([client, i, o["bw"].id, col, c, constructed])
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
                "name": odata["name"],
                "collection_name": odata["collection_name"],
                "email": email,
            }
        )
        odata["bw"] = ret
    return org, odata["bw"]


def record(client, i, oid, col, card, constructed):
    payload = {
        "externalId": card["card"]["id"],
        "object": "org-collection",
        "name": card["name"],
        "organizationId": oid,
    }
    ret = client.create(**payload)
    return ret


if __name__ == "__main__":
    main()
# vim:set et sts=4 ts=4 tw=120:
