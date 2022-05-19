#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import copy
import json
import os
import re
import traceback
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
BW_ORGA_NAME = os.environ.get("BW_ORGA_NAME", "bitwarden")
DONE = {"contructed": OrderedDict(), "errors": OrderedDict()}
SKIPPED_USERS = os.environ.get("BITWARDEN_VAULTIER_SKIP_USERS", "[+]old[^@]+@").strip()
AL = bwclient.CollectionAccess


class NameNotFound(RuntimeError):
    """."""


def add_to_collection(client, email, cid, aclargs):
    collection = aclargs["collection"]
    try:
        L.info(f"Adding {email} to collection: {collection.name}/{collection.id}")
        ret = client.set_collection_access(
            email, aclargs["collection"], **aclargs["payload"]
        )
        return {(email, cid): ret}
    except Exception as exc:
        trace = traceback.format_exc()
        L.error(f"Error while creating {email}\n{collection.name}\n{trace}")
        DONE["errors"][(email, cid)] = (exc, trace)


def add_to_orga(client, email, oid, aclargs):
    orga = aclargs["orga"]
    try:
        L.info(f"Adding {email} to orga: {orga.name}/{orga.id}")
        ret = client.set_organization_access(
            email, aclargs["orga"], **aclargs["payload"]
        )
        return {(email, oid): ret}
    except Exception as exc:
        trace = traceback.format_exc()
        L.error(f"Error while creating {email}\n{orga.name}\n{trace}")
        DONE["errors"][(email, oid)] = (exc, trace)


def do_accept_invitations(client, email, oid, aclargs):
    orga = aclargs["orga"]
    try:
        L.info(f"Confirm invitation of {email} to {orga.name}/{orga.id}")
        ret = client.accept_invitation(aclargs["orga"], email)
        return {(email, oid): ret}
    except Exception as exc:
        trace = traceback.format_exc()
        L.error(f"Error while inviting {email}\n{orga.name}\n{trace}")
        DONE["errors"][(email, oid)] = (exc, trace)


def do_confirm_invitations(client, email, oid, aclargs):
    orga = aclargs["orga"]
    try:
        L.info(f"Confirming {email} to {orga.name}/{orga.id}")
        ret = client.confirm_invitation(aclargs["orga"], email)
        return {(email, oid): ret}
    except Exception as exc:
        trace = traceback.format_exc()
        L.error(f"Error while confirming {email}\n{orga.name}\n{trace}")
        DONE["errors"][(email, oid)] = (exc, trace)


@click.command()
@click.argument("jsonf", default=JSON)
@click.option("--server", default=bitwardentools.SERVER)
@click.option("--email", default=bitwardentools.EMAIL)
@click.option("--password", default=bitwardentools.PASSWORD)
@click.option("--assingleorg", " /-S", default=AS_SINGLE_ORG, is_flag=True)
@click.option("--skippedusers", default=SKIPPED_USERS)
def main(jsonf, server, email, password, assingleorg, skippedusers):
    skipped_users_re = re.compile(skippedusers)
    L.info("start")
    client = Client(vaultier=True)
    if skippedusers:
        skippedusers = re.compile(skippedusers)
    client.sync()
    users_orgas = {}
    users_collections = {}
    caccesses = {}
    al = set()
    orgas = {}
    for jsonff in jsonf.split(":"):
        with open(jsonff) as fic:
            data = json.load(fic)
        orga = OrderedDict()
        collections = None
        oacls = data["acls"]
        if assingleorg:
            organ = data["name"]
            orga = client.get_organization(organ)
            collections = client.get_collections(orga=orga, sync=True)
        else:
            oacls = OrderedDict([(k, v) for k, v in oacls.items() if v >= 200])
        coacls = oacls
        for iv, vdata in enumerate(data["vaults"]):
            if collections is None:
                collections = client.get_collections(orga=orga, sync=True)
            v = vdata["name"]
            vacls = vdata["acls"]
            if not vdata["cards"]:
                L.info(f"Skipping {v} as it has no cards")
                continue
            if not assingleorg:
                orga = client.get_organization(v)
                coacls = copy.deepcopy(oacls)
                coacls.update(vacls)
            oadmins = [a for a in coacls if coacls[a] == 200]
            eorga = orgas.setdefault(orga.id, {"orga": orga, "emails": set()})
            for email, acle in coacls.items():
                if skipped_users_re.search(email):
                    log = f"{email} is old user, skipping"
                    continue
                payload = {}
                payload["access_level"] = AL.admin
                if int(acle) >= 200:
                    payload["accessAll"] = True
                if skippedusers and skippedusers.search(email):
                    L.info(f"{email} is skipped")
                    continue
                log = None
                eorga["emails"].add(email)
                try:
                    uaccess = client.get_accesses({"user": email, "orga": orga})
                except bwclient.NoAccessError:
                    bwacl = None
                else:
                    oaccess = uaccess["oaccess"]
                    bwacl = oaccess["daccess"].get(email, None)
                if (
                    bwacl
                    and (bwacl["type"] in [AL.admin, AL.manager])
                    and (payload["access_level"] == bwacl["type"])
                ):
                    log = f"User {email} is already in orga {orga.name} with right acls"
                if log:
                    if log not in al:
                        L.info(log)
                    al.add(log)
                    continue
                access = {"orga": orga, "payload": payload}
                ak = (orga.id, email)
                users_orgas[ak] = access
            for cdata in vdata["cards"]:
                cn = sanitize(cdata["name"])
                vc = cn
                if assingleorg:
                    vc = f"{v} {cn}"
                collection = client.get_collection(
                    vc, collections=collections, orga=orga
                )
                try:
                    caccess = caccesses[collection.id]
                except KeyError:
                    caccess = caccesses[collection.id] = client.get_accesses(collection)
                cacls = copy.deepcopy(vacls)
                cacls.update(cdata["acls"])
                for email, cacl in cacls.items():
                    eorga["emails"].add(email)
                    if skippedusers and skippedusers.search(email):
                        L.info(f"{email} is skipped")
                        continue
                    log = None
                    if email in oadmins:
                        continue
                    if skipped_users_re.search(email):
                        log = f"{email} is old user, skipping"
                    if email in caccess["emails"]:
                        log = f"User {email} is already in collection {collection.name}"
                    if log:
                        if log not in al:
                            L.info(log)
                        al.add(log)
                        continue
                    payload = {}
                    access = {"collection": collection, "payload": payload}
                    ak = (collection.id, email)
                    caccess = caccesses[collection.id] = client.get_accesses(collection)
                    users_collections[ak] = access

    # either create or edit passwords
    parallel = as_bool(os.environ.get("BW_PARALLEL_IMPORT", "1"))
    # parallel = False
    processes = int(os.environ.get("BW_PARALLEL_IMPORT_PROCESSES", "10"))

    constructed = OrderedDict()

    # invite users to orga
    record = add_to_orga
    # users_orgas = dict([(k, users_orgas[k]) for i, k in enumerate(users_orgas) if i<3])
    L.info("add_to_orga")
    if parallel:
        with Pool(processes=processes) as pool:
            res = pool.starmap_async(
                record,
                [
                    (client, email, oid, aclargs)
                    for (oid, email), aclargs in users_orgas.items()
                ],
            )
            res.wait()
            for ret in res.get():
                if not ret:
                    continue
                constructed.update(ret)
    else:
        for (oid, email), aclargs in users_orgas.items():
            ret = record(client, email, oid, aclargs)
            if not ret:
                continue
            constructed.update(ret)

    # invite users to collection
    record = add_to_collection
    L.info("add_to_collection")
    # users_collections = dict([(k, users_collections[k]) for i, k in enumerate(users_collections) if i < 13])
    if parallel:
        with Pool(processes=processes) as pool:
            res = pool.starmap_async(
                record,
                [
                    (client, email, cid, aclargs)
                    for (cid, email), aclargs in users_collections.items()
                ],
            )
            res.wait()
            for ret in res.get():
                if not ret:
                    continue
                constructed.update(ret)
    else:
        for (cid, email), aclargs in users_collections.items():
            ret = record(client, email, cid, aclargs)
            if not ret:
                continue
            constructed.update(ret)

    # autoaccept user invitation
    accept_invitations = OrderedDict()
    for orga, odata in orgas.items():
        oaccess = client.get_accesses(odata["orga"])
        for email in odata["emails"]:
            try:
                acl = oaccess["daccess"][email]
            except KeyError:
                continue
            else:
                # status: Invited = 0, Accepted = 1, Confirmed = 2,
                if acl["status"] == 0:
                    accept_invitations[(orga, email)] = {"orga": odata["orga"]}

    record = do_accept_invitations
    L.info("do_accept_invitations")
    # users_collections = dict([(k, users_collections[k]) for i, k in enumerate(users_collections) if i < 13])
    if parallel:
        with Pool(processes=processes) as pool:
            res = pool.starmap_async(
                record,
                [
                    (client, email, oid, aclargs)
                    for (oid, email), aclargs in accept_invitations.items()
                ],
            )
            res.wait()
            for ret in res.get():
                if not ret:
                    continue
                constructed.update(ret)
    else:
        for (oid, email), aclargs in accept_invitations.items():
            ret = record(client, email, oid, aclargs)
            if not ret:
                continue
            constructed.update(ret)

    # autoconfirm user invitation
    confirm_invitations = OrderedDict()
    for orga, odata in orgas.items():
        oaccess = client.get_accesses(odata["orga"])
        for email in odata["emails"]:
            try:
                acl = oaccess["daccess"][email]
            except KeyError:
                continue
            else:
                # status: Invited = 0, Accepted = 1, Confirmed = 2,
                if acl["status"] == 1:
                    confirm_invitations[(orga, email)] = {"orga": odata["orga"]}

    record = do_confirm_invitations
    L.info("do_confirm_invitations")
    # users_collections = dict([(k, users_collections[k]) for i, k in enumerate(users_collections) if i < 13])
    if parallel:
        with Pool(processes=processes) as pool:
            res = pool.starmap_async(
                record,
                [
                    (client, email, oid, aclargs)
                    for (oid, email), aclargs in confirm_invitations.items()
                ],
            )
            res.wait()
            for ret in res.get():
                if not ret:
                    continue
                constructed.update(ret)
    else:
        for (oid, email), aclargs in confirm_invitations.items():
            ret = record(client, email, oid, aclargs)
            if not ret:
                continue
            constructed.update(ret)
    return constructed


if __name__ == "__main__":
    main()
# vim:set et sts=4 ts=4 tw=0:
