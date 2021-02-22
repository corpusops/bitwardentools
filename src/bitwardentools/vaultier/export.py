#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import base64
import json
import os
import re
from zipfile import ZIP_DEFLATED, ZipFile

from vaultcli.auth import Auth
from vaultcli.client import Client
from vaultcli.main import write_binary_file, write_json_file

import bitwardentools
from bitwardentools import CFG, EXPORT_DIR, L, as_bool

bitwardentools.setup_logging()


def configure_client(config_file=CFG):
    verify = bool(os.environ.get("VAULTIER_VERIFY", ""))
    http_user = os.environ.get("VAULTIER_HTTP_USER", "")
    http_password = os.environ.get("VAULTIER_HTTP_PASSWORD", "")
    email = os.environ["VAULTIER_EMAIL"]
    server = os.environ["VAULTIER_URL"]
    key = base64.b64decode(os.environ["VAULTIER_KEY"])
    token = Auth(
        server, email, key, verify, http_user=http_user, http_password=http_password
    ).get_token()
    return Client(
        server, token, key, verify, http_user=http_user, http_password=http_password
    )


def export_workspace(client, workspace_id=None):
    if workspace_id is None:
        workspace_id = os.environ.get("VAULTIER_WORKSPACE_ID", "1")
    raw = as_bool(os.environ.get("VAULTIER_RAW", "1"))
    try:
        workspace = client.get_workspace(workspace_id)
    except Exception as e:
        raise SystemExit(e)
    directory = EXPORT_DIR
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory)
        except Exception as e:
            raise SystemExit(e)
    if not raw:
        zip_filename = "{}.{}.{}".format(workspace.id, workspace.name, "zip")
        try:
            zipfile = ZipFile(os.path.join(directory, zip_filename), "w", ZIP_DEFLATED)
        except Exception as e:
            raise SystemExit(e)
    workspace_data = {
        "id": workspace.id,
        "name": workspace.name,
        "description": workspace.description,
        "acls": workspace.acls,
        "vaults": [],
    }
    workspace_fn = re.sub(" |'", "__", workspace.name)
    json_file = os.path.join(directory, "{}.json".format(workspace_fn))
    pretty_json_file = json_file.replace(".json", ".pretty.json")
    vaults = client.list_vaults(workspace.id)
    L.info(f"Exporting {workspace.name} / {workspace.id}")
    for idx, vault in enumerate(vaults):
        vault_data = {
            "id": vault.id,
            "name": vault.name,
            "description": vault.description,
            "color": vault.color,
            "acls": vault.acls,
            "cards": [],
        }
        L.info("Export vault {name}/{id}".format(**vault_data))
        cards = client.list_cards(vault.id)
        for card in cards:
            card_data = {
                "id": card.id,
                "name": card.name,
                "description": card.description,
                "acls": card.acls,
                "secrets": [],
            }
            L.info("Export card {0[name]}/{1[name]}".format(vault_data, card_data))
            secrets = client.list_secrets(card.id)
            for secret in secrets:
                secret = client.decrypt_secret(secret, workspace.workspaceKey)
                secret_data = {
                    "id": secret.id,
                    "name": secret.name,
                    "type": secret.type,
                }
                L.info(
                    "Export card {0[name]}/{1[name]}{2[name]}".format(
                        vault_data, card_data, secret_data
                    )
                )
                if secret.data:
                    secret_data["data"] = secret.data
                if secret.blobMeta:
                    secret_data["blob_meta"] = secret.blobMeta
                    secret_file = client.get_file(secret.id)
                    if secret_file != [None, None]:
                        try:
                            os.makedirs(
                                os.path.join(directory, str(secret.id)), exist_ok=True
                            )
                            file_name = os.path.join(
                                directory, str(secret.id), secret_file[0]
                            )
                            write_binary_file(file_name, secret_file[1])
                        except Exception as e:
                            raise SystemExit(e)
                        if not raw:
                            zipfile.write(
                                file_name, os.path.join(str(secret.id), secret_file[0])
                            )
                            os.remove(file_name)
                            os.rmdir(os.path.join(directory, str(secret.id)))
                card_data["secrets"].append(secret_data)
            vault_data["cards"].append(card_data)
        workspace_data["vaults"].append(vault_data)
    try:
        write_json_file(json_file, workspace_data)
    except Exception as e:
        raise SystemExit(e)
    with open(json_file.replace(".json", ".pretty.json"), "w") as file:
        json.dump(workspace_data, file, indent=2, sort_keys=True)
    if not raw:
        zipfile.write(json_file, os.path.basename(json_file))
        zipfile.write(json_file, os.path.basename(pretty_json_file))
        os.remove(json_file)
        os.remove(pretty_json_file)
        zipfile.close()

    L.info(f"Exported {workspace.name} / {workspace.id}")


def export_workspaces(client, workspace_ids=None):
    if workspace_ids is None:
        workspace_ids = os.environ.get("VAULTIER_WORKSPACE_IDS", "1").split(":")
    for workspace_id in workspace_ids:
        export_workspace(client, workspace_id=workspace_id)


def main():
    L.info("start")
    client = configure_client(CFG)
    export_workspaces(client)


if __name__ == "__main__":
    main()

# vim:set et sts=4 ts=4 tw=80:
