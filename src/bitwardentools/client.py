#!/usr/bin/env python
"""
API client Alike wrapper around @bitwarden/cli npm package bu also with local implementation
Tested with cli version 1.14.0
"""
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import enum
import itertools
import json
import os
import re
import secrets
import traceback
from base64 import b64decode, b64encode
from collections import OrderedDict
from copy import deepcopy
from subprocess import run
from time import time

import requests
from jwt import encode as jwt_encode

from bitwardentools import crypto as bwcrypto
from bitwardentools.common import L, caseinsentive_key_search

VAULTIER_FIELD_ID = "vaultiersecretid"
DEFAULT_CACHE = {"id": {}, "name": {}, "sync": False}
SYNC_ALL_ORGAS_ID = "__orga__all__ORGAS__"
SYNC_ORGA_ID = "__orga__{0}"
SECRET_CACHE = {"id": {}, "name": {}, "vaultiersecretid": {}, "sync": []}
DEFAULT_BITWARDEN_CACHE = {
    "sync": {},
    "templates": {},
    "users": deepcopy(DEFAULT_CACHE),
    "organizations": deepcopy(DEFAULT_CACHE),
    "collections": {"sync": False, SYNC_ALL_ORGAS_ID: deepcopy(DEFAULT_CACHE)},
    "ciphers": {
        "sync": False,
        "by_cipher": deepcopy(SECRET_CACHE),
        "by_collection": {},
        "by_organization": {},
    },
}
CACHE = deepcopy(DEFAULT_BITWARDEN_CACHE)
FILTERED_ATTRS = re.compile("^_|^vaultier|^json$")
TYPES_MAPPING = {"org-collection": "orgcollection"}
REVERSE_TYPES_MAPPING = dict([(v, k) for k, v in TYPES_MAPPING.items()])
SERVER = os.environ.get("BITWARDEN_SERVER")
PRIVATE_KEY = os.environ.get("BITWARDEN_PRIVATE_KEY") or None
EMAIL = os.environ.get("BITWARDEN_EMAIL")
PASSWORD = os.environ.get("BITWARDEN_PW")
ADMIN_PASSWORD = os.environ.get("BITWARDEN_ADMIN_PASSWORD", "")
ADMIN_USER = os.environ.get("BITWARDEN_ADMIN_USER", "")
CUUID = os.environ.get("BITWARDEN_CLIENT_UUID", "42042042-0042-0042-0042-420004200042")
TYPMAPPER = {
    "organization": "organization",
    "collection": "collection",
    "orgccollection": "collection",
    "cipher": "cipher",
    "cipherdetails": "cipher",
    "item": "cipher",
    "card": "cipher",
    "note": "cipher",
    "securenote": "cipher",
    "identity": "cipher",
    "login": "cipher",
    "profile": "profile",
    "user": "profile",
}
COLTYPMAPPER = {
    "organization": "organizations",
    "collection": "collections",
    "orgcollection": "collections",
    "user": "users",
    "profiles": "users",
    "profile": "users",
    "cipher": "ciphers",
    "cipherdetails": "ciphers",
    "item": "ciphers",
    "card": "ciphers",
    "note": "ciphers",
    "securenote": "ciphers",
    "login": "ciphers",
}
ORGA_PERMISSIONS = {
    "accessBusinessPortal": False,
    "accessEventLogs": False,
    "accessImportExport": False,
    "accessReports": False,
    "manageAllCollections": False,
    "manageAssignedCollections": False,
    "manageGroups": False,
    "manageSso": False,
    "managePolicies": False,
    "manageUsers": False,
}


def uncapitzalize(s):
    if not s or not isinstance(s, str):
        return s
    return s[0].lower() + s[1:]


def clibase64(item):
    if not isinstance(item, str):
        item = json.dumps(item)
    enc = b64encode(item.encode()).replace(b"\n", b"")
    return enc.decode()


def strip_dict_data(data, skip=None):
    if skip and isinstance(skip, list):
        skip = "|".join(skip)
    if skip:
        skip = re.compile(skip)
    data = deepcopy(data)
    if isinstance(data, dict):
        for d in [a for a in data]:
            if skip and skip.search(d):
                data.pop(d, None)
                continue
            data[d] = strip_dict_data(data[d], skip=skip)
    elif isinstance(data, (list, tuple, set)):
        a = []
        for i in data:
            a.append(strip_dict_data(i, skip=skip))
        data = type(data)(a)
    return data


def rewrite_acls_collection(i, skip=None):
    if skip and isinstance(skip, list):
        skip = "|".join(skip)
    if skip:
        skip = re.compile(skip)
    if isinstance(i, dict):
        for v, k in {
            "Data": "data",
            "Id": "id",
            "AccessAll": "accessAll",
            "Email": "email",
            "Name": "name",
            "Status": "status",
            "Collections": "collections",
            "UserId": "userId",
            "Type": "type",
            "HidePasswords": "hidePasswords",
            "ReadOnly": "readOnly",
        }.items():
            if skip and (skip.search(v) or skip.search(k)):
                i.pop(v, None)
                i.pop(k, None)
            try:
                i[k] = rewrite_acls_collection(i.pop(v), skip=skip)
            except KeyError:
                continue
        return i
    elif isinstance(i, list):
        for idx in range(len(i)):
            i[idx] = rewrite_acls_collection(i[idx], skip=skip)
    return i


class BitwardenError(Exception):
    """."""


class ConfirmationAcceptError(BitwardenError):
    """."""

    email = None
    orga = None


class AlreadyConfirmedError(ConfirmationAcceptError):
    """."""


class PostConfirmedError(ConfirmationAcceptError):
    """."""

    response = None


class InvitationAcceptError(BitwardenError):
    """."""

    email = None
    orga = None


class AlreadyInvitedError(InvitationAcceptError):
    """."""


class PostInvitedError(InvitationAcceptError):
    """."""

    response = None


class BitwardenUncacheError(BitwardenError):
    """."""


class BitwardenInvalidInput(BitwardenError):
    """."""

    inputs = None


class ResponseError(BitwardenError):
    """."""

    response = None


class UnimplementedError(BitwardenError):
    """."""


class DecryptError(bwcrypto.DecryptError):
    """."""


class SearchError(BitwardenError):
    """."""

    criteria = None


class OrganizationNotFound(SearchError):
    """."""


class CollectionNotFound(SearchError):
    """."""


class SecretNotFound(SearchError):
    """."""


class ColSecretsSearchError(SearchError):
    """."""


class SecretSearchError(SearchError):
    """."""


class UserNotFoundError(SearchError):
    """."""


class ColSearchError(SearchError):
    """."""


class RunError(BitwardenError):
    """."""


class NoOrganizationKeyError(BitwardenError):
    """."""

    instance = None


class NoSingleItemForNameError(BitwardenError):
    """."""

    instance = None


class NoSingleOrgaForNameError(NoSingleItemForNameError):
    """."""


class NoSingleCollectionForNameError(NoSingleItemForNameError):
    """."""


class NoAttachmentsError(BitwardenError):
    """."""

    instance = None


class LoginError(ResponseError):
    """."""


class DeleteError(ResponseError):
    """."""


class CiphersError(ResponseError):
    pass


class BitwardenValidateError(BitwardenError):
    """."""

    email = None


class BitwardenPostValidateError(ResponseError, BitwardenValidateError):
    """."""


class CliRunError(BitwardenError):
    """."""

    process = None


class CliLoginError(LoginError, CliRunError):
    """."""

    process = None


class AlreadyExitingUserError(RunError):
    """."""


class NoAccessError(BitwardenError):
    """."""

    objects = None


def _get_obj_type(t):
    o = t.replace("-", "").lower().capitalize()
    obj = globals()[o]
    assert issubclass(obj, BWFactory)
    return o, obj


def get_obj_type(t):
    return _get_obj_type(t)[0]


def get_obj(t):
    return _get_obj_type(t)[1]


def get_bw_type(t):
    o = get_obj_type(t).lower()
    return REVERSE_TYPES_MAPPING.get(o, o)


def get_types(t):
    return {"obj": get_obj_type(t), "bw": get_bw_type(t)}


def get_type(obj, default=""):
    if isinstance(obj, BWFactory):
        objtyp = getattr(obj, "Object", getattr(obj, "object", ""))
    elif isinstance(obj, dict):
        objtyp = obj.get("Object", obj.get("object", ""))
    else:
        objtyp = default
    return objtyp.lower()


def get_bw_cipher_type(obj):
    if isinstance(obj, Item):
        bwciphertyp = obj.__class__.__name__.lower()
    else:
        bwciphertyp = get_type(obj)
    cipher_type = SECRETS_CLASSES_STR[bwciphertyp]
    return cipher_type


def unmarshall_value(value, cycle=0):
    if isinstance(value, (tuple, list)):
        nvalue = type(value)([unmarshall_value(a, cycle + 1) for a in value])
    elif isinstance(value, dict):
        nvalue = type(value)()
        for k, val in value.items():
            nvalue[uncapitzalize(k)] = unmarshall_value(val, cycle + 1)
    else:
        nvalue = value
    return nvalue


class BWFactory(object):
    def __init__(
        self,
        jsond=None,
        client=None,
        vaultier=False,
        vaultiersecretid=None,
        unmarshall=False,
    ):
        if unmarshall:
            jsond = unmarshall_value(jsond)
        self._client = client
        self.json = jsond
        if vaultiersecretid:
            vaultier = True
        for k in ["vaultier", "vaultiersecretid"]:
            setattr(self, k, jsond.pop(k, locals()[k]))
        self.broken_objs = OrderedDict()

    def delete(self, client):
        return client.delete(self)

    def reflect(self):
        for i, v in [
            a for a in self.__dict__.items() if not FILTERED_ATTRS.match(a[0])
        ]:
            self.json[i] = v
        for i in [a for a in self.json if FILTERED_ATTRS.match(a)]:
            self.json.pop(i)
        return self

    def load(self, jsond=None):
        if jsond is None:
            jsond = self.json
        if jsond:
            for i, val in jsond.items():
                setattr(self, i, val)
        if self.vaultiersecretid:
            self.vaultier = True
        fields = getattr(self, "fields", []) or []
        for itm in fields:
            for i in [a for a in itm]:
                val = itm[i]
                if hasattr(val, "decode"):
                    val = val.decode()
                    itm[i] = val
        if self.vaultiersecretid or fields:
            try:
                item = None
                for itm in fields:
                    if itm["name"] == VAULTIER_FIELD_ID:
                        item = itm
                        break
                if item:
                    if self.vaultiersecretid:
                        item["value"] = f"{self.vaultiersecretid}"
                    self.vaultiersecretid = item["value"]
                if self.vaultiersecretid:
                    if not item:
                        fields.append(
                            {
                                "value": f"{self.vaultiersecretid}",
                                "type": 0,
                                "name": VAULTIER_FIELD_ID,
                            }
                        )
                    self.vaultier = True
                    setattr(self, "fields", fields)
            except AttributeError:
                pass
        return self

    @classmethod
    def construct(
        kls,
        jsond,
        vaultier=None,
        vaultiersecretid=None,
        unmarshall=False,
        object_class=None,
        client=None,
        *a,
        **kw,
    ):
        if object_class is None:
            try:
                object_class_name = jsond["object"]
            except KeyError:
                object_class_name = jsond["Object"]
            if object_class_name.lower().startswith("cipher"):
                try:
                    typ = jsond["Type"]
                    object_class = SECRETS_CLASSES[typ]
                except KeyError:
                    L.error(f'Unkown cipher {jsond.get("Id", "")}')
            else:
                object_class = get_obj(object_class_name)
        a = object_class(
            jsond,
            vaultier=vaultier,
            vaultiersecretid=vaultiersecretid,
            unmarshall=unmarshall,
            client=client,
        )
        return a.load()

    @classmethod
    def patch(kls, action, client, bwtype=None, add_template=True, token=None, **jsond):
        token = client.get_token(token=token)
        if bwtype is None:
            bwtype = get_bw_type(jsond["object"])
        otype = get_obj_type(bwtype)
        smethod = f"{action}_{otype.lower()}"
        try:
            api_method = getattr(client, smethod)
        except AttributeError:
            api_method = None
        if api_method:
            add_template = False
        jsond["object"] = bwtype
        if add_template:
            jsond = client.get_template(**jsond)
        obj = kls.construct(jsond).reflect()
        log = f"{action.capitalize()}ed"
        if not api_method:
            tpl = {}
            for k in [key for key in jsond]:
                try:
                    tpl[k] = getattr(obj, k)
                except AttributeError:
                    continue
            enc = b64encode(json.dumps(tpl).encode())
            denc = enc.decode()
            cmd = f"{action} {bwtype}"
            if action == "edit":
                cmd += f' {tpl["id"]}'
            orgaid = jsond.get("organizationId", "")
            if orgaid:
                orga = client.get_organization(orgaid, token=token)
                organ = isinstance(orga, Organization) and orga.name or orga
                cmd += f" --organizationid {client.item_or_id(orga)}"
                log += f" in orga {organ}"
            cmd += f" {denc}"
            try:
                ret = client.call(cmd, asjson=True, load=True)
            except (CliRunError,):
                trace = traceback.format_exc()
                raise CliRunError(trace)
            log += f": {otype}: {ret.name}/{ret.id}"
            L.info(log)
        else:
            ret = api_method(**jsond)
        return ret

    @classmethod
    def create(kls, client, *args, **kw):
        return kls.patch("create", client, *args, **kw)

    @classmethod
    def edit(kls, client, *args, **kw):
        return kls.patch("edit", client, *args, **kw)


class CipherType(enum.IntEnum):
    Login = 1
    Card = 3
    Note = 2
    Identity = 4


class CollectionAccess(enum.IntEnum):
    owner = 0
    admin = 1
    manager = 3
    user = 2


class Profile(BWFactory):
    """."""


class Organization(BWFactory):
    """."""

    def __init__(self, *a, **kw):
        ret = super(Organization, self).__init__(*a, **kw)
        self._complete = False
        return ret


class Cipher(BWFactory):
    """."""


class Cipherdetails(Cipher):
    """."""


class Item(Cipherdetails):
    """."""

    def load(self, jsond=None):
        super(Item, self).load(jsond)
        if self.vaultier:
            sid = [
                a["value"]
                for a in self.json.get("fields", [])
                if a.get("name", "") == VAULTIER_FIELD_ID
            ]
            if sid:
                sid = sid[0]
            else:
                sid = None
            self.vaultiersecretid = sid
        return self


class Attachment(Item):
    """."""


class Login(Item):
    """."""


class Note(Item):
    """."""


SecureNote = Note
Securenote = Note


class Identity(Item):
    """."""


class Card(Item):
    """."""


class Folder(BWFactory):
    """."""


SECRETS_CLASSES = {
    CipherType.Login: Login,
    CipherType.Card: Card,
    CipherType.Note: Note,
    CipherType.Identity: Identity,
}

SECRETS_CLASSES_STR = {
    "login": CipherType.Login,
    "card": CipherType.Card,
    "note": CipherType.Note,
    "identity": CipherType.Identity,
}


class Collection(BWFactory):
    """."""

    def __init__(self, *a, **kw):
        BWFactory.__init__(self, *a, **kw)
        self.externalId = getattr(self, "externalId", None)
        self._orga = None
        self.reflect()

    def load(self, *a, **kw):
        super(Collection, self).load(*a, **kw)
        if self._client and getattr(self, "organizationId"):
            try:
                self._orga = self._client.get_organization(self.organizationId)
            except OrganizationNotFound:
                pass
        return self


Orgcollection = Collection


class Client(object):
    def __init__(
        self,
        server=SERVER,
        email=EMAIL,
        password=PASSWORD,
        admin_user=ADMIN_USER,
        admin_password=ADMIN_PASSWORD,
        private_key=PRIVATE_KEY,
        client_id="python",
        client_uuid=CUUID,
        login=True,
        cache=None,
        vaultier=False,
    ):
        # goal is to allow shared cache amongst client instances
        # but also if we want totally isolated caches
        if cache is None:
            cache = CACHE
        if not email:
            raise RunError("no email")
        if not server:
            raise RunError("no server")
        if not password:
            raise RunError("no password")
        self.admin_user = admin_user
        self.admin_password = admin_password
        self._broken_ciphers = OrderedDict()
        self.vaultier = vaultier
        self.server = server
        if not private_key:
            private_key = None
        self.private_key = private_key
        if self.private_key:
            if hasattr(self.private_key, "encode"):
                self.private_key = b64decode(self.private_key)
        self.password = password
        self.email = email.lower()
        self.sessions = OrderedDict()
        self.client_id = client_id
        self.client_uuid = client_uuid
        self.templates = {}
        self._cache = cache
        self.tokens = {}
        if login:
            self.login()

    @property
    def token(self):
        return self.tokens.get(self.email, None)

    @token.setter
    def token_set(self, value):
        self.tokens[self.email] = value
        return self.tokens[self.email]

    def adminr(
        self,
        uri,
        method="post",
        headers=None,
        admin_user=None,
        admin_password=None,
        *a,
        **kw,
    ):
        admin_user = admin_user or self.admin_user
        admin_password = admin_password or self.admin_password
        if admin_user and admin_password:
            kw["auth"] = (admin_user, admin_password)
        url = uri
        if not url.startswith("http"):
            url = f"{self.server}/admin{uri}"
        if headers is None:
            headers = {}
        return getattr(requests, method.lower())(url, headers=headers, *a, **kw)

    def r(self, uri, method="post", headers=None, token=None, retry=True, *a, **kw):
        url = uri
        if not url.startswith("http"):
            url = f"{self.server}{uri}"
        if headers is None:
            headers = {}
        if token is not False:
            token = self.get_token(token)
            headers.update({"Authorization": f"Bearer {token['access_token']}"})
        resp = getattr(requests, method.lower())(url, headers=headers, *a, **kw)
        if resp.status_code in [401] and token is not False and retry:
            L.debug(
                f"Access denied, trying to retry after refreshing token for {token['email']}"
            )
            token = self.login(token["email"], token["password"])
            headers.update({"Authorization": f"Bearer {token['access_token']}"})
            resp = getattr(requests, method.lower())(url, headers=headers, *a, **kw)
        return resp

    def login(
        self,
        email=None,
        password=None,
        scope="api offline_access",
        grant_type="password",
    ):
        email = email or self.email
        try:
            token = self.tokens[email]
        except KeyError:
            pass
        else:
            # as token is already there, test if token is still usable
            resp = self.r(
                "/api/accounts/revision-date", token=token, retry=False, method="get"
            )
            try:
                self.assert_bw_response(resp)
            except ResponseError:
                self.tokens.pop(email, None)
            else:
                token["_btw_login_count"] += 1
                return token
        password = password or self.password
        data = self.r("/api/accounts/prelogin", json={"email": email}, token=False)
        jdata = data.json()
        iterations = caseinsentive_key_search(jdata, "kdfiterations")
        hashed_password, master_key = bwcrypto.hash_password(
            password, email, iterations=iterations
        )
        loginpayload = {
            "scope": scope,
            "client_id": self.client_id,
            "grant_type": grant_type,
            "username": email,
            "password": hashed_password,
            "deviceType": 9,
            "deviceIdentifier": self.client_uuid,
            "deviceName": "pyinviter",
        }
        data = self.r("/identity/connect/token", token=False, data=loginpayload)
        if not data.status_code == 200:
            exc = LoginError(f"Failed login for {email}")
            exc.response = data
            raise exc
        token = data.json()
        token["_btw_login_count"] = 1
        token["iterations"] = iterations
        token["password"] = password
        token["hashed_password"] = hashed_password
        token["master_key"] = master_key
        token["email"] = email
        for k, f in {"Key": "user_key", "PrivateKey": "orgs_key"}.items():
            key = k != "PrivateKey" and master_key or token.get("user_key")
            token[f] = bwcrypto.decrypt(token[k], key)
        self.tokens[email] = token
        return token

    def item_or_id(self, item_or_id):
        if isinstance(item_or_id, BWFactory):
            item_or_id = item_or_id.id
        return item_or_id

    def raw_call(self, *args, **kw):
        kw.setdefault("no_session", True)
        kw.setdefault("asjson", False)
        kw.setdefault("sync", False)
        return self.call(*args, **kw)

    def cli_login(self, email=None, password=None, force=False):
        password, email = password or self.password, email or self.email
        session = self.sessions.get(email, None)
        if (session is None) or force:
            ret = self.raw_call(f"config server {self.server}")
            try:
                ret = self.raw_call(f"login {email} {password}")
            except CliRunError as exc:
                sret = exc.args[0].decode()
                if "already" in sret:
                    try:
                        ret = self.raw_call(f"unlock {password}")
                    except CliRunError as exc:
                        cexc = CliLoginError(exc.args[0])
                        cexc.process = ret
                        raise cexc
                    sret = ret.stdout.decode()
                else:
                    raise LoginError("{email} cli login error")
            sret = ret.stdout.decode()
            s = (
                [a for a in sret.splitlines() if "BW_SESSION=" in a][0]
                .split()[-1]
                .split('"')[1]
            )
            session = self.sessions[email] = s
        return session

    def call(
        self,
        cli,
        input=None,
        asjson=True,
        capture_output=True,
        load=False,
        shell=True,
        sync=False,
        force_login=False,
        no_session=False,
        user=None,
        email=None,
        vaultier=None,
    ):
        vaultier = self.get_vaultier(vaultier)
        if force_login or not no_session:
            os.environ["BW_SESSION"] = self.cli_login(user, email, force=force_login)
        else:
            sync = False
        if sync or (cli and cli.startswith("sync")):
            self.cli_sync()
        if input is None:
            input = f"{self.password}".encode()
        env = os.environ.copy()
        L.debug(f"Running bw {cli}")
        ret = run(
            f"bw {cli}",
            input=input,
            capture_output=capture_output,
            env=env,
            shell=shell,
        )
        if ret.returncode != 0:
            exc = CliRunError(ret.stdout + ret.stderr)
            exc.process = ret
            raise exc
        if asjson:
            try:
                ret = json.loads(ret.stdout)
            except json.decoder.JSONDecodeError:
                exc = CliRunError(
                    f"is not json\n"
                    f"{ret.stdout.decode()}\n"
                    f"{ret.stderr.decode()}\n"
                )
                exc.process = ret
                raise exc
            if load:
                if isinstance(ret, (list, tuple)):
                    ret = type(ret)(
                        [
                            BWFactory.construct(r, client=self, vaultier=vaultier)
                            for r in ret
                        ]
                    )
                elif isinstance(ret, dict):
                    ret = BWFactory.construct(ret, client=self, vaultier=vaultier)
        return ret

    def get_template(self, otype=None, **kw):
        if otype is None:
            otype = kw["object"]
        otype = get_obj_type(otype)
        bwt = get_bw_type(otype)
        try:
            tpl = self._cache["templates"][otype]
        except KeyError:
            tpl = self._cache["templates"][otype] = self.call(f"get template {bwt}")
        tpl = deepcopy(tpl)
        tpl.update(kw)
        return tpl

    def api_sync(self, sync=None, cache=None, token=None):
        _CACHE = self._cache["sync"]
        k = "api_sync"
        token = self.get_token(token)
        if sync is None:
            sync = False
        if cache is None:
            cache = True
        if cache is False or sync:
            _CACHE[k] = False
        try:
            assert _CACHE.get(k)
        except AssertionError:
            L.debug("api_sync")
            resp = self.r(
                "/api/sync",
                json={"excludeDomains": True},
                method="get",
                token=token,
            )
            self.assert_bw_response(resp)
            _CACHE.update(resp.json())
            _CACHE[k] = True
        return _CACHE

    def cli_sync(self, sync=None):
        return self.call("sync", asjson=False)

    def sync(self, sync=None, token=None):
        return self.api_sync(sync=sync, token=token)

    def finish_orga(self, orga, cache=None, token=None, complete=None):
        token = self.get_token(token)
        if complete and not getattr("orga", "BillingEmail", "") and not orga._complete:
            orga = BWFactory.construct(
                self.r(f"/api/organizations/{orga.id}", method="get").json(),
                client=self,
                unmarshall=True,
            )
            orga._complete = True
            self.cache(orga)
        return orga

    def get_organizations(self, sync=None, cache=None, token=None):
        token = self.get_token(token)
        _CACHE = self._cache["organizations"]
        if sync is None:
            sync = False
        if cache is None:
            cache = True
        if cache is False or sync:
            _CACHE["sync"] = False
        try:
            assert _CACHE.get("sync")
        except AssertionError:
            sdata = self.api_sync(sync=sync)
            for orga in sdata.get("Profile", {}).get("Organizations", []):
                orga = deepcopy(orga)
                orga["Object"] = "organization"
                obj = BWFactory.construct(orga, client=self, unmarshall=True)
                self.cache(obj)
            _CACHE["sync"] = True
        return _CACHE

    def get_organization(self, orga, sync=None, cache=None, token=None, complete=None):
        token = self.get_token(token)
        if isinstance(orga, Organization):
            if not sync:
                return orga
            else:
                orga = orga.id
        _id = self.item_or_id(orga)
        if isinstance(_id, str):
            _id = _id.lower()
        try:
            return self.finish_orga(
                self._cache["organizations"]["id"][_id],
                token=token,
                cache=cache,
                complete=complete,
            )
        except KeyError:
            organizations = self.get_organizations(sync=sync, cache=cache)
        try:
            return self.finish_orga(
                organizations["id"][_id], token=token, cache=cache, complete=complete
            )
        except KeyError:
            pass
        try:
            orgas = organizations["name"][_id]
            if len(orgas) > 1:
                exc = NoSingleOrgaForNameError(f"More that one orga with {_id} name.")
                exc.instance = organizations
                raise exc
            for a, v in orgas.items():
                return self.finish_orga(v, token=token, cache=cache, complete=complete)
        except KeyError:
            pass
        exc = OrganizationNotFound(f"No such organization found {orga}")
        exc.criteria = [orga]
        raise exc

    def get_token(self, token=None):
        token = token or self.token
        if not token:
            token = self.login()
        return token

    def decrypt_item(self, val, key, decode=True, charset=None):
        if isinstance(val, str):
            if bwcrypto.SYM_ENCRYPTED_STRING_RE.match(val):
                val = bwcrypto.decrypt(val, key)
                if decode and hasattr(val, "decode"):
                    val = charset and val.decode(charset) or val.decode()
        elif isinstance(val, dict):
            nval = type(val)()
            for k, v in val.items():
                nval[k] = self.decrypt_item(v, key, decode=decode)
            val = nval
        elif isinstance(val, (list, tuple)):
            val = type(val)([self.decrypt_item(v, key, decode=decode) for v in val])
        return val

    def encrypt_item(self, val, key):
        if isinstance(val, str):
            val = bwcrypto.encrypt_sym(val, key)
        elif isinstance(val, dict):
            nval = type(val)()
            for k, v in val.items():
                if k not in [
                    "id",
                    "organizationId",
                    "lastKnownRevisionDate",
                    "revisionDate",
                    "deleteDate",
                    "deletedDate",
                    "collectionIds",
                ]:
                    v = self.encrypt_item(v, key)
                nval[k] = v
            val = nval
        elif isinstance(val, (list, tuple)):
            val = type(val)([self.encrypt_item(v, key) for v in val])
        return val

    def _cache_objects(
        self, items, cache_key=None, cache=None, attributes=None, uniques=None, id_=None
    ):
        if not isinstance(items, (list, tuple)):
            items = [items]
        if cache is None:
            cache = self._cache
        if cache_key:
            cache = cache.setdefault(cache_key, deepcopy(DEFAULT_CACHE))
        if not uniques:
            uniques = ["id", "externalId", "vaultiersecretid"]
        if attributes is None:
            attributes = ["id", "name"]
        attributes = list(set(attributes + uniques))
        for a in attributes:
            subcache = cache.setdefault(a, OrderedDict())
            if not items:
                continue
            for item in items:
                if not hasattr(item, a):
                    continue
                itemid = id_ or item.id
                identifier = getattr(item, a)
                if identifier and (a in ["vaultiersecretid"]):
                    identifier = str(identifier)
                if isinstance(identifier, str):
                    identifier = identifier.lower()
                if a in uniques:
                    if not identifier:
                        continue
                    subcache[identifier] = item
                else:
                    subsubcache = subcache.setdefault(identifier, OrderedDict())
                    subsubcache[itemid] = item
        return cache

    _cache_object = _cache_objects

    def cache_user(self, r, **kw):
        return self._cache_objects(r, cache_key="users", uniques=["id", "email"])

    def cache_organization(self, r, **kw):
        return self._cache_objects(r, "organizations")

    def cache_collection(self, r, cache_key=SYNC_ALL_ORGAS_ID, **kw):
        return self._cache_objects(
            r, cache=self._cache["collections"], cache_key=cache_key, **kw
        )

    def add_cipher(self, ret, obj, **kw):
        return self._cache_object(obj, cache=ret)

    def cache_cipher(self, r, vaultier=True, **kw):
        scache = self._cache["ciphers"]
        self._cache_object(r, cache=scache["by_cipher"])
        for cid in getattr(r, "collectionIds"):
            self._cache_object(
                r, cache=scache["by_collection"].setdefault(cid, deepcopy(SECRET_CACHE))
            )
        for oid in [a for a in [getattr(r, "organizationId")] if a]:
            self._cache_object(
                r,
                cache=scache["by_organization"].setdefault(oid, deepcopy(SECRET_CACHE)),
            )
        return scache

    def cache(self, obj, **kw):
        ret = []
        if not isinstance(obj, (list, tuple, set)):
            obj = [obj]
        for i in obj:
            if isinstance(i, Profile):
                cache_method = self.cache_user
            elif isinstance(i, Collection):
                cache_method = self.cache_collection
            elif isinstance(i, Organization):
                cache_method = self.cache_organization
            elif isinstance(i, Item):
                cache_method = self.cache_cipher
            else:
                cache_method = None
            if cache_method:
                ret.append(cache_method(i, **kw))
        return ret

    def _upload_object(self, uri, data, key=None, log=None, method="post"):
        resp = self.r(uri, json=data, method=method)
        self.assert_bw_response(resp)
        jsond = resp.json()
        if key:
            jsond = self.decrypt_item(jsond, key)
        obj = BWFactory.construct(jsond=jsond, client=self, unmarshall=True)
        if not log:
            log = f"Created {obj.object}"
        log += f"{obj.id}"
        self.cache(obj)
        L.info(log)
        return obj

    def _edit(self, *a, **kw):
        kw.setdefault("method", "put")
        return self._upload_object(*a, **kw)

    _patch = _edit

    def create_item(
        self,
        name,
        orga=None,
        last_known_revision_date=None,
        favorite=False,
        collections=None,
        cipher_type=CipherType.Login,
        method="post",
        token=None,
        **jsond,
    ):
        name_or_obj = name
        if isinstance(name_or_obj, BWFactory):
            obj = name_or_obj
            cipher_type = get_bw_cipher_type(obj)
            name = getattr(obj, "name", "")
            for k, v in name_or_obj.json.items():
                jsond.setdefault(k, v)
        else:
            name = name_or_obj
            obj = None
        oid, suf = jsond.get("organizationId", None) or orga, ""
        token = self.get_token(token)
        collections = collections or []
        for i in jsond.get("collectionIds", []) or []:
            if i not in collections:
                collections.append(i)
        actionpre = {"post": "creat", "put": "edit"}.get(method, method)
        if oid:
            orga = self.get_organization(oid, token=token)
            oid = orga.id
            _, key = self.get_organization_key(orga, token=token)
            log = f"{actionpre.capitalize()}ing in orga {orga.name} cipher: "
            suf = "/admin"
        else:
            log = "{action} cipher: "
            key = token["user_key"]

        login = jsond.get("login", {}) or {}
        uris = login.get("uris")
        name = jsond.get("name", name)
        username = login.get("username", "")
        if name:
            log += f" {name}"
        else:
            name = "cipher"
            if orga:
                name = f"{orga.name} {name}"
            if username:
                name += f" @{username}"
            if uris:
                name += " "
                name += " ".join([f'{u["uri"]}' for u in uris])
        jsond["name"] = name
        if username:
            log += f" @{username}"
        if uris:
            log += " uris:"
            log += " ".join([f'{u["uri"]}' for u in uris])
        log += " / "
        data = self.encrypt_item(jsond, key)
        data["type"] = int(cipher_type)
        data.setdefault("favorite", favorite)
        data["lastKnownRevisionDate"] = last_known_revision_date
        data["organizationId"] = oid
        for i in ["object"]:
            data.pop(i, None)
        # edit cipher
        if method == "put":
            rd = data.pop("revisionDate", None)
            if not data.get("lastKnownRevisionDate", None):
                data["lastKnownRevisionDate"] = rd
            u = f'/api/ciphers/{data["id"]}'
            for i in ["edit", "data"]:
                data.pop(i, None)
        else:
            if orga:
                data = {
                    "cipher": data,
                    "collectionIds": [
                        self.get_collection(c, orga=orga, token=token).id
                        for c in collections
                    ],
                }
            u = f"/api/ciphers{suf}"
        obj = self._upload_object(u, method=method, data=data, key=key, log=log)
        return obj

    create_login = create_item

    def create_card(self, *a, **kw):
        kw["cipher_type"] = 3
        return self.create_item(*a, **kw)

    def create_identity(self, *a, **kw):
        kw["cipher_type"] = 4
        return self.create_item(*a, **kw)

    def create_securenote(self, *a, **kw):
        kw["cipher_type"] = 2
        return self.create_item(*a, **kw)

    def edit_item(self, *a, **kw):
        kw["method"] = "put"
        return self.create_item(*a, **kw)

    edit_login = edit_item

    def edit_card(self, *a, **kw):
        kw["cipher_type"] = 3
        return self.edit_item(*a, **kw)

    def edit_identity(self, *a, **kw):
        kw["cipher_type"] = 4
        return self.edit_item(*a, **kw)

    def edit_securenote(self, *a, **kw):
        kw["cipher_type"] = 2
        return self.edit_item(*a, **kw)

    def edit_organization(self, orga, token=None, **jsond):
        """
        jsond possible keys: {"name":"foo","businessName":null,"billingEmail":"foo@foo.net"}
        """
        token = self.get_token(token)
        obj = self.finish_orga(self.get_organization(orga), complete=True)
        data = deepcopy(jsond)
        log = f'Editing organization {data["name"]}/{obj.id}'
        data.update(jsond)
        for i, v in {
            "name": obj.name,
            "businessName": obj.businessName,
            "billingEmail": obj.billingEmail,
        }.items():
            data.setdefault(i, v)
        obj = self._upload_object(
            f"/api/organizations/{obj.id}", data, log=log, method="put"
        )
        self.cache(obj)
        return obj

    def create_organization(
        self,
        name,
        email=None,
        collection_name=None,
        collection_key=None,
        plan_type=0,
        token=None,
        **jsond,
    ):
        if collection_name is None:
            collection_name = f"C: {name}"
        if collection_key is None:
            collection_key = secrets.token_bytes(64)
        email = email or self.email
        token = self.get_token(token)
        encoded_key = bwcrypto.encrypt_asym(collection_key, token["orgs_key"])
        encoded_collection_name = bwcrypto.encrypt_sym(collection_name, collection_key)
        data = {
            "key": encoded_key,
            "collectionName": encoded_collection_name,
            "name": name,
            "billingEmail": email,
            "planType": plan_type,
        }
        log = f'Creating organization {data["name"]}/'
        data.update(jsond)
        obj = self._upload_object(
            "/api/organizations", data, key=collection_key, log=log
        )
        self.cache(obj)
        return obj

    def get_organization_key(self, orga, token=None, sync=None):
        keys = self._cache["organizations"].setdefault("keys", {})
        if sync is None:
            sync = False
        if not isinstance(orga, Organization):
            orga = self.get_organization(orga, sync=sync)
        try:
            return keys[orga.id]
        except KeyError:
            token = self.get_token(token)
            for sync in [sync, True]:
                sdata = self.api_sync(sync=sync)
                enc_okey = (
                    dict(
                        [
                            (a["Id"], a)
                            for a in sdata.get("Profile", {}).get("Organizations", [])
                        ]
                    )
                    .get(orga.id, {})
                    .get("Key", None)
                )
                if enc_okey:
                    break
            if enc_okey:
                try:
                    okey = bwcrypto.decrypt(enc_okey, token["orgs_key"])
                except bwcrypto.DecryptError:
                    self.broken_objs[orga.id] = enc_okey
                ret = keys[orga.id] = enc_okey, okey
                return ret
        exc = NoOrganizationKeyError(
            f"No encryption key for {orga.id}, please unlock or be confirmed"
        )
        exc.instance = orga
        raise exc

    def edit_orgcollection(self, collection, token=None, **jsond):
        """
        jsond possible keys: {"name":"foo","groups":[]}
        """
        token = self.get_token(token)
        obj = self.get_collection(collection)
        data = deepcopy(jsond)
        log = f'Editing collection {data["name"]}/{obj.id}'
        data.update(jsond)
        for i, v in {
            "name": obj.name,
            "groups": [],
        }.items():
            data.setdefault(i, v)
        if not bwcrypto.SYM_ENCRYPTED_STRING_RE.match(data["name"]):
            _, k = self.get_organization_key(obj._orga, token=token)
            data["name"] = bwcrypto.encrypt(bwcrypto.CIPHERS.sym, data["name"], k)
        obj = self._upload_object(
            f"/api/organizations/{obj._orga.id}/collections/{obj.id}",
            data,
            log=log,
            key=k,
            method="put",
        )
        self.cache(obj)
        return obj

    def create_orgcollection(
        self, name, organizationId=None, orga=None, externalId=None, token=None, **jsond
    ):
        orga = self.get_organization(organizationId or orga)
        token = self.get_token(token)
        _, k = self.get_organization_key(orga, token=token)
        encoded_name = bwcrypto.encrypt(bwcrypto.CIPHERS.sym, name, k)
        data = {"externalId": [], "groups": [], "name": encoded_name}
        log = "Creating :"
        if orga:
            log += f" in orga: {orga.name}/{orga.id}:"
        log += f" collection {name}/"
        data.update(jsond)
        return self._upload_object(
            f"/api/organizations/{orga.id}/collections", data, key=k, log=log
        )

    create_collection = create_orgcollection
    edit_collection = edit_orgcollection

    def get_collections(self, orga=None, sync=None, cache=None, token=None):
        """
        orga is either None for all or an orga(or orgaid)
        """
        token = self.get_token(token)
        if not orga:
            sync_key = SYNC_ALL_ORGAS_ID
        else:
            orga = self.get_organization(orga)
            sync_key = SYNC_ORGA_ID.format(orga.id)
        _CACHE = self._cache["collections"]
        if sync is None:
            sync = False
        if cache is None:
            cache = True
        if cache is False or sync:
            _CACHE["sync"] = False
            _CACHE.pop(sync_key, None)
            _CACHE.pop(SYNC_ALL_ORGAS_ID, None)
        try:
            return _CACHE[sync_key]
        except KeyError:
            pass
        #
        self.api_sync(sync=sync)
        #
        try:
            assert _CACHE["sync"]
        except AssertionError:
            for enccol in (
                self.r("/api/collections", method="get").json().get("Data", [])
            ):
                col = BWFactory.construct(enccol, client=self, unmarshall=True)
                _, colk = self.get_organization_key(col.organizationId, token=token)
                col.name = bwcrypto.decrypt(col.name, colk).decode()
                col.reflect()
                self.cache_collection(col)
            _CACHE["sync"] = True
        #
        if orga:
            orga = self.get_organization(orga)
            for r in [
                col
                for col in _CACHE[SYNC_ALL_ORGAS_ID]["id"].values()
                if col.organizationId == orga.id
            ]:
                self.cache_collection(r, cache_key=sync_key)
        ret = self.cache_collection([], cache_key=sync_key)
        _CACHE[sync_key] = ret
        #
        return ret

    def get_collection(
        self,
        item_or_id_or_name=None,
        externalId=None,
        collections=None,
        sync=False,
        orga=None,
        token=None,
    ):
        criteria = [item_or_id_or_name, orga]
        token = self.get_token(token)
        if orga:
            orga = self.get_organization(orga, token=token)
        if isinstance(item_or_id_or_name, Collection):
            if not sync:
                return item_or_id_or_name
            else:
                item_or_id_or_name = item_or_id_or_name.id
                externalId = None
        _id = self.item_or_id(item_or_id_or_name)
        if collections is None:
            if orga is None:
                exc = ColSearchError("At least collections or orga/orgaid")
                exc.criteria = criteria
            collections = self.get_collections(orga, sync=sync, token=token)
        if not (_id or externalId):
            exc = ColSearchError(
                "collectionsearch: At least id/item/name or externalId"
            )
            exc.criteria = criteria
            raise exc
        if isinstance(_id, str):
            _id = _id.lower()
        if isinstance(externalId, str):
            externalId = externalId.lower()
        if _id:
            try:
                return collections["id"][_id]
            except (KeyError, IndexError):
                pass
            try:
                items = collections["name"][_id]
                if orga:
                    items = OrderedDict(
                        [
                            (k, v)
                            for k, v in items.items()
                            if v.organizationId == orga.id
                        ]
                    )
                if len(items) > 1:
                    exc = NoSingleCollectionForNameError(
                        f"More that one collection with {_id} name."
                    )
                    exc.instance = items
                    raise exc
                for a, v in items.items():
                    return v
            except KeyError:
                pass
        if externalId:
            try:
                return collections["externalId"][externalId]
            except KeyError:
                pass
        log = f"No such collection found {_id}/{externalId}"
        if orga:
            log += f" in orga: {orga.id}/{orga.name}"
        exc = CollectionNotFound(log)
        exc.criteria = [_id, externalId, orga]
        raise exc

    def decrypt(
        self, value, key=None, orga=None, token=None, recursion=None, dictkey=None
    ):
        token = self.get_token(token=token)
        nvalue = value
        idv = id(value)
        if recursion is None:
            recursion = []
        if not nvalue:
            return nvalue
        elif isinstance(value, (bool, int, float)):
            return nvalue
        elif idv in recursion:
            L.debug(f"Cycle detected, returning value: {nvalue}")
            return nvalue
        elif isinstance(value, dict):
            nvalue = type(value)()
            obj = get_type(value)
            if obj and not orga and re.search("^passsword|note|attachment|cipher", obj):
                key = token["user_key"]
            if orga is None:
                for i in "OrganizationId", "organizationId":
                    if not value.get(i, None):
                        continue
                    try:
                        orga = self.get_organization(value[i])
                    except OrganizationNotFound:
                        pass
            if orga:
                _, key = self.get_organization_key(orga)
            for i, v in value.items():
                nvalue[i] = self.decrypt(
                    v,
                    orga=orga,
                    key=key,
                    token=token,
                    recursion=recursion,
                    dictkey=i,
                )

        elif isinstance(value, (tuple, list)):
            nvalue = type(value)(
                [
                    self.decrypt(
                        v, orga=orga, key=key, token=token, recursion=recursion
                    )
                    for v in value
                ]
            )
        elif isinstance(value, str) and bwcrypto.is_encrypted(value):
            if not key:
                raise DecryptError("Can't decrypt: key missing")
            nvalue = bwcrypto.decrypt(value, key)
            if dictkey and (dictkey.lower() not in ["key"]):
                nvalue = nvalue.decode()
        recursion.append(idv)
        return nvalue

    def get_ciphers(
        self,
        collection=None,
        vaultier=None,
        collections=None,
        orga=None,
        sync=None,
        token=None,
        cache=None,
    ):
        vaultier = self.get_vaultier(vaultier)
        token = self.get_token(token=token)
        scache = self._cache["ciphers"]
        if sync or cache is False:
            scache.pop("sync", None)
        if orga:
            orga = self.get_organization(orga, sync=sync, token=token)
        if collection:
            collection = self.get_collection(
                collection, collections=collections, orga=orga, sync=sync, token=token
            )
        try:
            assert scache.get("sync")
        except AssertionError:
            self.api_sync(sync=sync, cache=cache)
            try:
                resp = self.r("/api/ciphers", token=token, method="get")
                self.assert_bw_response(resp)
                ciphers = resp.json()
            except ResponseError:
                raise
            except json.JSONDecodeError:
                exc = CiphersError("ciphers are not in json")
                exc.response = resp
                raise exc
            dciphers = []
            for cipher in ciphers.get("Data", []):
                try:
                    dciphers.append(self.decrypt(cipher, token=token))
                except bwcrypto.DecryptError:
                    self._broken_ciphers[cipher["Id"]] = cipher
                    L.info(f'Cant decrypt cipher {cipher["Id"]}, broken ?')
            for cipher in dciphers:
                obj = BWFactory.construct(cipher, client=self, unmarshall=True)
                self.cache(obj, vaultier=vaultier)
            scache["sync"] = True
        if collection:
            return scache["by_collection"].get(collection.id, {})
        elif orga:
            return scache["by_organization"].get(orga.id, {})
        else:
            return scache["by_cipher"]

    def get_attachments(
        self,
        item,
        collection=None,
        collections=None,
        orga=None,
        vaultier=None,
        token=None,
    ):
        vaultier = self.get_vaultier(vaultier)
        token = self.get_token(token)
        sec = self.get_cipher(
            item,
            collection=collection,
            collections=collections,
            orga=orga,
            vaultier=vaultier,
            token=token,
        )
        try:
            ret = sec.attachments
            assert ret is not None
            return ret
        except (AttributeError, AssertionError):
            exc = NoAttachmentsError()
            exc.instance = sec
            raise exc

    def delete_attachment(
        self,
        item,
        attachment,
        collection=None,
        collections=None,
        orga=None,
        vaultier=None,
        token=None,
    ):
        vaultier = self.get_vaultier(vaultier)
        token = self.get_token(token)
        sec = self.get_cipher(
            item,
            collection=collection,
            collections=collections,
            orga=orga,
            vaultier=vaultier,
            token=token,
        )
        aid = attachment
        if isinstance(aid, dict):
            aid = aid["id"]
        res = self.r(f"/api/ciphers/{sec.id}/attachment/{aid}", method="delete")
        self.assert_bw_response(res)
        L.info('Deleted {attachment["fileName"]}/{attachment["id"]')
        return res

    def delete_attachments(
        self,
        item,
        attachments,
        collection=None,
        collections=None,
        orga=None,
        vaultier=None,
        token=None,
    ):
        vaultier = self.get_vaultier(vaultier)
        token = self.get_token(token)
        ret = []
        if not isinstance(attachments, list):
            attachments = [attachments]
        for a in attachments:
            ret.append(
                self.delete_attachment(
                    item,
                    a,
                    collection=collection,
                    collections=collections,
                    orga=orga,
                    vaultier=vaultier,
                    token=token,
                )
            )
        return ret

    def attach(
        self,
        item,
        filepath,
        collection=None,
        collections=None,
        orga=None,
        vaultier=None,
        token=None,
    ):
        vaultier = self.get_vaultier(vaultier)
        token = self.get_token(token)
        fn = os.path.basename(filepath)
        try:
            attachments = self.get_attachments(
                item,
                collection=collection,
                collections=collections,
                orga=orga,
                vaultier=vaultier,
                token=token,
            )
            to_delete = []
            for attachment in attachments:
                if attachment["fileName"] == fn:
                    to_delete.append(attachment)
            self.delete_attachments(item, to_delete, token=token)
        except NoAttachmentsError:
            pass
        L.info(f"Attaching {fn} to {item.name}/{item.id}")
        oid = getattr(item, "organizationId", None)
        if oid:
            _, key = self.get_organization_key(oid)
        else:
            key = token["user_key"]
        attachment_key = secrets.token_bytes(64)
        encoded_attachment_key = bwcrypto.encrypt_sym(attachment_key, key)
        encoded_attachment_name = bwcrypto.encrypt_sym(fn, key)
        data = {"key": encoded_attachment_key}
        with open(filepath, "rb") as f:
            ct = f.read()
            files = {
                "data": (
                    encoded_attachment_name,
                    bwcrypto.encrypt_sym_to_bytes(ct, attachment_key),
                    "application/octet-stream",
                )
            }
            res = self.r(
                f"/api/ciphers/{item.id}/attachment",
                method="post",
                data=data,
                files=files,
            )
        self.assert_bw_response(res)
        return res

    def get_vaultier(self, vaultier):
        if vaultier is None:
            vaultier = self.vaultier
        return vaultier

    def get_cipher(
        self,
        item_or_id_or_name,
        collection=None,
        collections=None,
        orga=None,
        as_list=False,
        vaultier=None,
        sync=None,
        token=None,
    ):
        if isinstance(item_or_id_or_name, Item):
            if not sync:
                return item_or_id_or_name
            else:
                item_or_id_or_name = item_or_id_or_name.id
        vaultier = self.get_vaultier(vaultier)
        token = self.get_token(token)
        _id = f"{self.item_or_id(item_or_id_or_name)}"
        if isinstance(_id, str):
            _id = _id.lower()
        ret = None
        if collection:
            collection = self.get_collection(
                collection, collections=collections, orga=orga, token=token
            )

        s = self.get_ciphers(
            collection=collection, vaultier=vaultier, orga=orga, sync=sync, token=token
        )
        if vaultier:
            try:
                ret = [s["vaultiersecretid"][_id]]
            except KeyError:
                pass
        if not ret:
            try:
                ret = [s["id"][_id]]
            except KeyError:
                pass
        if not ret:
            try:
                ret = s["name"][_id].values()
            except KeyError:
                pass
        if ret:
            if not as_list:
                ret = ret[0]
            return ret
        if collection is not None:
            # try to search cipher in global if not found
            try:
                return self.get_cipher(
                    _id,
                    collections=collections,
                    orga=orga,
                    vaultier=vaultier,
                    sync=sync,
                    token=token,
                )
            except SecretNotFound:
                # but still let 1 collection error message trigger the exception
                pass
        collectionn = (
            isinstance(collection, Collection) and collection.name or collection
        )
        exc = SecretNotFound(f"No such cipher found {_id} in collection {collectionn}")
        exc.criteria = [_id, collection, orga]
        raise exc

    def patch(self, *args, **kw):
        return BWFactory.patch(self, *args, **kw)

    def create(self, *args, **kw):
        return BWFactory.create(self, *args, **kw)

    def edit(self, *args, **kw):
        return BWFactory.edit(self, *args, **kw)

    def link(
        self,
        ciphers,
        relcollections,
        collections=None,
        orga=None,
        token=None,
        link=True,
    ):
        ret = []
        token = self.get_token(token)
        if not isinstance(ciphers, list):
            ciphers = [ciphers]
        if not relcollections:
            return
        if collections is None:
            collections = self.get_collections(orga, token=token)
        if relcollections and not isinstance(relcollections, list):
            relcollections = [relcollections]
        relcollections = [
            self.get_collection(c, collections=collections, orga=orga, token=token)
            for c in relcollections
        ]
        if relcollections:
            ciphers = [
                self.get_cipher(
                    s, collection=relcollections[0], collections=collections, orga=orga
                )
                for s in ciphers
            ]
        else:
            ciphers = [
                self.get_cipher(s, collections=collections, orga=orga) for s in ciphers
            ]

        for cipher in ciphers:
            colids = list(set([a for a in cipher.collectionIds]))
            relcolids = dict([(a.id, a) for a in relcollections])
            if link:
                ret = [relcolids[a] for a in relcolids if a not in colids]
                todo = colids + [a.id for a in ret]
            else:
                ret = [relcolids[a] for a in colids if a in relcolids]
                todo = [a for a in colids if a not in relcolids]
            for relcollection in ret:
                msg = (
                    link
                    and (
                        f"Will link cipher {cipher.name}/{cipher.id}"
                        f" to {relcollection.name}/{relcollection.id}"
                    )
                    or (
                        f"cipher {cipher.name}/{cipher.id} will be unlinked"
                        f" to {relcollection.name}/{relcollection.id}"
                    )
                )
                L.info(msg)
            if todo == colids:
                L.warn("Every colleciton link is already in place")
            else:
                cipher.collectionIds = todo
                L.info(f"Applying collections for {cipher.name}/{cipher.id}")
                cipher.reflect()
                res = self.r(
                    f"/api/ciphers/{cipher.id}/collections",
                    method="put",
                    token=token,
                    json={"collectionIds": cipher.collectionIds},
                )
                self.assert_bw_response(res)
        return ret

    def unlink(self, *a, **kw):
        kw["link"] = False
        return self.link(*a, **kw)

    def delete(self, obj, typ=None, token=None, **kw):
        token = self.get_token(token)
        if not typ:
            objtyp = get_type(obj)
            if objtyp:
                typ = TYPMAPPER.get(objtyp.lower(), objtyp)
        assert isinstance(typ, str) and typ in TYPMAPPER.values()
        sid = "id: {_id}"
        if isinstance(obj, BWFactory):
            _id = getattr(obj, "id", "")
            name = getattr(obj, "name", sid)
        elif isinstance(obj, dict):
            _id = obj.get("id", "")
            name = obj.get("name", sid)
        else:
            _id = obj
            name = sid
        assert _id
        data = {"masterPasswordHash": self.token["hashed_password"].decode()}
        ret = {}
        self.uncache(typ=typ, ids=_id, **kw)
        resp = self.r(f"/api/{typ}s/{_id}", token=token, method="delete", json=data)
        try:
            self.assert_bw_response(resp, expected_status_codes=[200, 404])
            L.info(f"Deleted or already removed {typ}: {_id}/{name}")
            ret.setdefault(typ, []).append(_id)
        except AssertionError:
            exc = DeleteError(f"delete error {typ}: {_id}/{name}")
            exc.response = resp
            raise exc
        return ret

    def uncache(self, typ=None, ids=None, obj=None, cache=None, grandcaches=None, **kw):
        if grandcaches is None:
            grandcaches = []
        if cache is None:
            try:
                assert typ or ids or (obj and isinstance(obj, BWFactory))
            except AssertionError:
                raise BitwardenUncacheError("neither cache or typ or id or obj or ids")
        if not isinstance(ids, set):
            ids = ids is not None and set(ids) or set()
        if cache is None:
            if isinstance(obj, BWFactory) and not typ:
                typ = TYPMAPPER[get_type(obj, typ)].lower()
            cache = self._cache[COLTYPMAPPER[typ]]
        try:
            assert cache is not None
        except AssertionError:
            raise BitwardenUncacheError("no cache selected")
        if isinstance(obj, BWFactory):
            ids.add(obj.id)
        if not ids:
            _ = [ids.add(i) for i in cache.get("id", {})]
        grandcaches.append(cache)
        for k in [a for a in cache]:
            subval = cache[k]
            if isinstance(subval, dict):
                self.uncache(
                    ids=ids, typ=typ, cache=subval, grandcaches=grandcaches, **kw
                )
            elif isinstance(subval, BWFactory) and (subval.id in ids):
                cache.pop(k, None)
            elif k in ids:
                cache.pop(k, None)

    def warm_templates(self):
        for i in ["collection", "org-collection", "item"]:
            self.get_template(i)

    def refresh(self, token=None):
        token = self.get_token(token)
        self.sync(sync=True, token=token)
        self.get_organizations(cache=False, token=token)
        self.get_collections(cache=False, token=token)

    def download(self, attachment, directory=None, filename=None):
        if not directory:
            directory = os.getcwd()
        if not filename:
            filename = attachment["fileName"]
        dest = f"{directory}/{filename}"
        if not os.path.exists(directory):
            os.makedirs(directory)
        with open(dest, "wb") as fic:
            data = bwcrypto.decrypt_bytes(
                self.r(attachment["url"], method="get").content, attachment["key"]
            )
            fic.write(data)
        return dest

    def get_users(self, sync=None, **kw):
        if sync is None:
            sync = False
        cache = self._cache["users"]
        if sync:
            cache.pop("sync", False)
        try:
            assert cache["sync"]
        except (AssertionError, KeyError):
            resp = self.adminr("/users", method="get")
            self.assert_bw_response(resp, expected_status_codes=[200, 500])
            if resp.status_code in [500]:
                self.uncache(cache, **kw)
                json = []
            else:
                json = resp.json()
            for user in json:
                obj = BWFactory.construct(user, client=self, unmarshall=True)
                self.cache(obj)
            cache["sync"] = True
        return cache

    def get_user(self, email=None, name=None, id=None, user=None, sync=None):
        if email:
            email = email.lower()
        if isinstance(user, Profile):
            if not sync:
                return user
            else:
                id = user.id
                email = name = user = None
        assert email or name or id
        cache = self.get_users(sync=sync)
        try:
            if not id:
                raise KeyError()
            return cache["id"][id.lower()]
        except KeyError:
            try:
                if not email:
                    raise KeyError()
                return cache["email"][email]
            except KeyError:
                try:
                    if not name:
                        raise KeyError()
                    return cache["name"][name.lower()][0]
                except (IndexError, KeyError):
                    pass
        criteria = [email, name, id, user]
        exc = UserNotFoundError(f"user not found id:{id} / email:{email} / name:{name}")
        exc.criteria = criteria
        raise exc

    def assert_bw_response(
        self, response, expected_status_codes=None, expected_callback=None, *a, **kw
    ):
        if not expected_status_codes:
            expected_status_codes = [200]
        if not isinstance(expected_status_codes, list):
            expected_status_codes = [expected_status_codes]

        def default_expected_callback(x, *fargs, **fkw):
            assert x.status_code in expected_status_codes

        expected_callback = expected_callback or default_expected_callback

        try:
            expected_callback(response, *a, **kw)
        except Exception as orig_exc:
            msg = str(orig_exc)
            if not msg:
                msg = f"{response.reason}\n{response.text}"
            exc = ResponseError(msg)
            exc.response = response
            try:
                jdata = response.json()
                exc = ResponseError(
                    "\n".join(
                        list(
                            itertools.chain.from_iterable(
                                jdata["ValidationErrors"].values()
                            )
                        )
                    )
                )
                exc.orig_exc = exc
                exc.response = response
            except Exception:
                pass
            raise exc

    def post_user_request(self, resp, sync=True):
        self.assert_bw_response(resp)
        # reload cached users
        return self.get_users(sync=sync)

    def enable_user(self, email=None, name=None, id=None, user=None):
        user = self.get_user(email=email, name=name, id=id, user=user)
        resp = self.adminr(f"/users/{user.id}/enable")
        self.post_user_request(resp)
        L.info(f"Enabled user {user.email} / {user.name} / {user.id}")
        return resp

    def disable_user(self, email=None, name=None, id=None, user=None):
        user = self.get_user(email=email, name=name, id=id, user=user)
        resp = self.adminr(f"/users/{user.id}/disable")
        self.post_user_request(resp)
        L.info(f"Disabled user {user.email} / {user.name} / {user.id}")
        return resp

    def delete_user(self, email=None, name=None, id=None, user=None, sync=True, **kw):
        user = self.get_user(email=email, name=name, id=id, user=user, sync=sync)
        resp = self.adminr(f"/users/{user.id}/delete")
        self.post_user_request(resp)
        self.uncache(obj=user, **kw)
        L.info(f"Deleted user {user.email} / {user.name} / {user.id}")
        return resp

    def validate(self, email, password=None, id=None, name=None, sync=None, token=None):
        token = self.get_token(token=token)
        self.ensure_private_key()
        user = self.get_user(email=email, name=name, id=id, sync=sync)
        if not user.emailVerified:
            now = int(time())
            data = {
                "nbf": now,
                "exp": now + 432000,
                "iss": f"{self.server}|verifyemail",
                "sub": user.id,
            }
            private_key = bwcrypto.load_rsa_key(self.private_key)
            pem_private_key = private_key.exportKey("PEM")
            jwt = jwt_encode(data, pem_private_key, algorithm="RS256")
            payload = {"userId": user.id, "token": jwt}
            try:
                resp = self.r(
                    "/api/accounts/verify-email-token", json=payload, token=token
                )
                self.post_user_request(resp)
            except ResponseError as oexc:
                exc = BitwardenPostValidateError("validation response failed")
                exc.email = email
                exc.response = oexc.response
                raise exc
            try:
                user = self.get_user(email=user.email, sync=True)
                assert user.emailVerified
            except AssertionError:
                exc = BitwardenPostValidateError("validation did not complete")
                exc.email = email
                exc.response = resp
                raise exc
        L.info(f"Validated user {user.email} / {user.name} / {user.id}")
        return user

    def create_user(
        self,
        email,
        password=None,
        passwordlength=32,
        name=None,
        passwordhint=None,
        iterations=bwcrypto.ITERATIONS,
        auto_validate=True,
        **json,
    ):
        if email:
            email = email.lower()
        if not password:
            password = bwcrypto.gen_password(length=passwordlength)
        if not name:
            name = re.sub("[.+]", "", email.replace("@", "AT")).lower()
        try:
            self.get_user(email=email, name=name, sync=True)
            raise AlreadyExitingUserError(f"user email:{email} name:{name}")
        except UserNotFoundError:
            pass
        hashedpw, master_key = bwcrypto.hash_password(
            password, email, iterations=iterations
        )
        ekey, key = bwcrypto.make_sym_key(master_key)
        easymk, pub_asymk, priv_asymk = bwcrypto.make_asym_key(key)
        bpub_asymk = b64encode(pub_asymk).decode()
        payload = {
            "email": email,
            "kdf": 0,
            "kdfIterations": iterations,
            "masterPasswordHint": passwordhint,
            "masterPasswordHash": hashedpw.decode(),
            "name": name,
            "key": ekey,
            "keys": {"encryptedPrivateKey": easymk, "publicKey": bpub_asymk},
            "referenceData": {"id": None},
        }
        resp = self.r("/api/accounts/register", json=payload, token=False)
        self.post_user_request(resp)
        user = self.get_user(email=email)
        if auto_validate:
            user = self.validate(email, password)
        ret = user, password
        L.info(f"Created user {user.email} / {user.name} / {user.id}")
        return ret

    def edit_user(self, email=None, name=None, id=None, user=None, **json):
        user = self.get_user(email=email, name=name, id=id, user=user)
        raise UnimplementedError()

    def search(self, json_or_obj, types=None, sync=False, **kw):
        assert isinstance(json_or_obj, (dict, BWFactory))
        ret = OrderedDict()
        typ = get_type(json_or_obj)
        btyp = TYPMAPPER.get(typ, None)
        if isinstance(json_or_obj, dict):
            kw.update(json_or_obj.get("search_kwargs", {}))
        elif isinstance(json_or_obj, BWFactory):
            kw.update(getattr(json_or_obj, "search_kwargs", {}))
        kw.setdefault("sync", sync)
        if sync:
            kw.setdefault("cache", False)
        if btyp:
            types = [btyp]
        else:
            #  let this order as for deletion, we need to delete in this order
            types = types or ["cipher", "collection", "organization"]
        for btyp in types:
            getter = getattr(self, f"get_{btyp}s")
            items = getter(**kw)["id"]
            json_data = json_or_obj
            if isinstance(json_data, BWFactory):
                json_or_obj.reflect()
                json_data = json_data.json
            for id_, obj in items.items():
                add = True
                for knob, v in json_data.items():
                    if getattr(obj, knob) != v:
                        add = False
                if add:
                    ret[(btyp, obj.id)] = obj
        return ret

    def search_objects(self, json_or_obj, types=None, sync=False, limit=None, **kw):
        """
        same as search but returns as list
        """
        ret = []
        for ix, ((typ, i), obj) in enumerate(
            self.search(json_or_obj, types=types, sync=sync, **kw).items()
        ):
            if limit is not None and len(ret) > limit:
                break
            ret.append(obj)
        return ret[0:limit]

    def warm(self, sync=None, collections=None, users=None, ciphers=None, orgas=None):
        if (
            sync is None
            and collections is None
            and ciphers is None
            and orgas is None
            and users is None
        ):
            sync = True
        if sync is not None:
            collections = ciphers = users = orgas = sync
        ret = dict(
            users=self.get_users(sync=users),
            ciphers=self.get_ciphers(sync=ciphers),
            orgas=self.get_organizations(sync=orgas),
            collections=self.get_collections(sync=collections),
        )
        return ret

    def bust_cache(self):
        for k in [a for a in self._cache]:
            val = self._cache[k]
            self._cache[k] = 0
            del val
            self._cache.pop(k, None)
            self._cache.update(deepcopy(DEFAULT_BITWARDEN_CACHE))

    def get_accesses(self, objs, sync=None, token=None):
        """
        Can be called with those forms:
            get_accesses(c)
                    => return accesses in Collection c
            get_accesses(o)
                    => return accesses in Organization o
            get_accesses({"user": u, "orga": o})
                    => return the access for u in orga o
            get_accesses({"user": u, "collection": c})
                    => will return the orga access (not scopped to col)
                       (equivalent to get_accesses({"user": u, "orga": c.organizationId})
        objs can be either a single element or a list of elements
        return will be either a single access dicts, or a list of access dicts:
           {
                "emails": emails,      => indexed by emails: userorg ids
                "emailsr": emailsr,    => indexed by userorgids: emails
                "daccessr": daccessr,  => indexed by emails accesses
                                            for an org: list of cols,
                                            for a col: list of orgusers,
                                            for a user: list of cols
                "daccess": daccess,    => indexed by uuid accesses
                                            for an org: list of cols,
                                            for a col: list of orgusers,
                                            for a user: list of cols
                "acls": access,        => list of access (either collections for a user
                                            or users for an org or a collection)
                "access": access,      => raw accesses returned by API
                                            for an org: orgitemdetails,
                                            for a col: orgcol details
                                            for a user: userorgdetails
                "oaccess": oaccess,    => for a user or collection: relative orga access
                "raw": resp,
                "exception": exc,      => if an exception is raised: the exc object
            }
        """
        if sync is None:
            # XXX: maybe we will implement cache at a later time
            sync = True
        token = self.get_token(token)
        ret, single = OrderedDict(), False
        if not isinstance(objs, (list, set, tuple)):
            single = True
            objs = [objs]
        for o in objs:
            is_user = isinstance(o, dict)
            daccess, daccessr, oaccess, emails, emailsr = (
                OrderedDict(),
                OrderedDict(),
                None,
                {},
                {},
            )
            if not isinstance(o, (Collection, Organization, dict)):
                exc = BitwardenInvalidInput(
                    "One or more Inputs are not neither a collection or an organization or a dict"
                )
                exc.inputs = objs
                raise exc
            email = None
            if isinstance(o, Organization):
                orga = o
                objid = o.id
                u = f"/api/organizations/{o.id}/users"
            elif isinstance(o, Collection):
                objid = o.id
                orga = self.get_organization(o.organizationId, token=token)
                u = f"/api/organizations/{o.organizationId}/collections/{o.id}/users"
            elif is_user:
                email = o["user"]
                if isinstance(email, Profile):
                    email = email.email
                try:
                    orga = self.get_organization(o["orga"], token=token)
                except KeyError:
                    orga = self.get_organization(
                        self.get_collection(o["collection"], token=token).organizationId
                    )
                objid = f"{email}--{orga.id}"
            if not isinstance(o, Organization):
                try:
                    oaccess = ret[orga.id]
                except KeyError:
                    oaccess = self.get_accesses(orga, token=token)

            if is_user:
                try:
                    ouid = oaccess["emails"][email]
                except KeyError:
                    exc = NoAccessError(
                        f"{email} has no access to {orga.name}/{orga.id}"
                    )
                    raise exc
                u = f"/api/organizations/{orga.id}/users/{ouid}"
            resp = self.r(u, token=token, method="get", json={})
            try:
                self.assert_bw_response(resp)
                access, exc = resp.json(), None
            except ResponseError as exc:
                access, exc = None, exc
            access, acls = rewrite_acls_collection(access), []
            if isinstance(o, Collection):
                # collections call returns a list of user acls
                acls = access
            if isinstance(access, dict):
                if is_user:
                    emails[email] = ouid
                    emailsr[ouid] = email
                    acls = access.get("collections", [])
                else:
                    acls = access.get("data", [])
            if isinstance(o, Collection):
                for email, i in oaccess["daccess"].items():
                    if i.get("accessAll", False):
                        emails[email] = i["id"]
                        emailsr[i["id"]] = email
                        coacl = {
                            "id": i["id"],
                            "readOnly": False,
                            "hidePasswords": False,
                        }
                        daccessr[i["id"]] = coacl
                        daccess[email] = coacl
            if acls:
                for i in acls:
                    if isinstance(o, Organization):
                        email = i["email"]
                        emails[email] = i["id"]
                        emailsr[i["id"]] = email
                    if isinstance(o, Collection):
                        email = oaccess["emailsr"][i["id"]]
                        emails[email] = i["id"]
                        emailsr[i["id"]] = email
                    if not is_user:
                        daccessr[i["id"]] = i
                        daccess[email] = i
                    else:
                        daccessr[i["id"]] = i
                        daccess.setdefault(email, OrderedDict())[i["id"]] = i
            ret[objid] = {
                "emails": emails,
                "emailsr": emailsr,
                "daccessr": daccessr,
                "daccess": daccess,
                "access": access,
                "acls": acls,
                "oaccess": oaccess,
                "raw": resp,
                "exception": exc,
            }
        if single:
            for i in ret:
                return ret[i]
        return ret

    def remove_user_from_collection(self, emails_or_users, collections, token=None):
        ret = {}
        token = self.get_token(token)
        if not isinstance(collections, (list, tuple, set)):
            collections = [collections]
        if not isinstance(emails_or_users, (list, tuple, set)):
            emails_or_users = [emails_or_users]
        for u in emails_or_users:
            email, done = u, None
            if isinstance(email, Profile):
                email = email.email
            ret[email] = {}
            for collection in collections:
                collection = self.get_collection(collection, token=token)
                orga = self.get_organization(collection.organizationId, token=token)
                # if we get multiple emails/users with same id, be sure to refresh access every round
                access = self.get_accesses(collection, sync=True, token=token)
                emails = access["emails"]
                try:
                    iid = emails[email]
                except KeyError:
                    pass
                else:
                    newaccess = [a for a in access["acls"] if a["id"] != iid]
                    u = f"/api/organizations/{orga.id}/collections/{collection.id}/users"
                    done = self.r(u, method="put", json=newaccess, token=token)
                    self.assert_bw_response(done)
                ret[email][collection.id] = done
        return ret

    def remove_user_from_organization(self, emails_or_users, orgas, token=None):
        ret = {}
        token = self.get_token(token)
        if not isinstance(orgas, (list, tuple, set)):
            orgas = [orgas]
        for email in get_emails(emails_or_users):
            done = None
            ret[email] = {}
            for orga in orgas:
                orga = self.get_organization(orga, token=token)
                # if we get multiple emails/users with same id, be sure to refresh access every round
                access = self.get_accesses(orga, sync=True, token=token)
                emails = access["emails"]
                try:
                    iid = emails[email]
                except KeyError:
                    pass
                else:
                    u = f"/api/organizations/{orga.id}/users/{iid}"
                    done = self.r(u, method="delete", token=token)
                    self.assert_bw_response(done)
                ret[email][orga.id] = done
                return ret

    def _orga_args(
        self,
        token=None,
        access_level=None,
        sync=None,
        remove=None,
        accessAll=None,
        collections=None,
        permissions=None,
    ):
        token = self.get_token(token)
        if collections:
            if not isinstance(collections, (list, set, tuple)):
                collections = [collections]
        if access_level is None:
            access_level = CollectionAccess.user
        if accessAll is None:
            if collections:
                accessAll = False
            else:
                accessAll = access_level in (
                    CollectionAccess.owner,
                    CollectionAccess.admin,
                )
        if not isinstance(permissions, dict):
            permissions = {}
        for permission, v in ORGA_PERMISSIONS.items():
            permissions.setdefault(permission, v)
        for p in [a for a in permissions]:
            try:
                ORGA_PERMISSIONS[p]
            except KeyError:
                permissions.pop(p, None)
        if sync:
            self.warm(collections=True, orgas=True)
        if remove is None:
            remove = False
        return token, access_level, accessAll, permissions, remove, collections

    def add_user_to_organization(
        self,
        emails_or_users,
        orga,
        collections=None,
        token=None,
        sync=None,
        access_level=None,
        permissions=None,
        accessAll=None,
        readonly=False,
        hidepasswords=False,
    ):
        """
        emails_or_users: email or Profile to set access to
        accessAll: access all collections configuration knob
        readonly: global readonly setting for the call if unset specifically for a collection
        hidePasswords: global readonly setting for the call if unset specifically for a collection
        access_level (see bwclient.CollectionAccess for a readable enum: int for level access)
                (eg access_level=CollectionAccess.admin)
        collections: [list]
            items are  either:
                - collection
                - collectionId
                - a dict: {collection: col_or_id, [opt] readOnly: True/False, [opt] hidePasswords: True/False}
                - examples:
                    - Uu-ID-xx-xx
                    - Collection(...)
                    - {'collection': "U-U-I-D", readOnly: True, 'hidePasswords': False}
                    - {'collection': CollectionObj, readOnly: True, 'hidePasswords': False}
        permissions permissions have no effect for now, only global setting
                    owner/admin/manager/user ditacte what the ACLs are.
        """
        (
            token,
            access_level,
            accessAll,
            permissions,
            remove,
            collections,
        ) = self._orga_args(
            token=token,
            access_level=access_level,
            accessAll=accessAll,
            sync=sync,
            collections=collections,
            permissions=permissions,
        )
        orga = self.get_organization(orga, token=token)
        params = {
            "emails": get_emails(emails_or_users),
            "accessAll": accessAll,
            "type": access_level,
            "permissions": permissions,
            "collections": None,
        }
        if not accessAll:
            orga = self.get_organization(orga, token=token, sync=sync)
            dcollections = self.collections_to_payloads(
                collections, orga=orga, token=token
            )
            params["collections"] = self.compute_accesses(
                dcollections, readonly=readonly, hidepasswords=hidepasswords
            )["payloads"]
        u = f"/api/organizations/{orga.id}/users/invite"
        response = self.r(u, json=params, token=token)
        self.assert_bw_response(response)
        return response

    def set_organization_access(
        self,
        emails_or_users,
        orga,
        collections=None,
        token=None,
        sync=None,
        access_level=None,
        remove=False,
        permissions=None,
        accessAll=None,
        readonly=None,
        hidepasswords=None,
    ):
        """
        Variant to create or update organization at a USER level: manage it's type, and it's collections
        email: email or Profile to set access to
        accessAll: access all collections configuration knob
        readonly: global readonly setting for the call if unset specifically for a collection
        hidePasswords: global readonly setting for the call if unset specifically for a collection
        access_level (see bwclient.CollectionAccess for a readable enum: int for level access)
                (eg access_level=CollectionAccess.admin)
        collections: [list]
            items are  either:
                - collection
                - collectionId
                - a dict: {collection: col_or_id, [opt] readOnly: True/False, [opt] hidePasswords: True/False}
                - examples:
                    - Uu-ID-xx-xx
                    - Collection(...)
                    - {'collection': "U-U-I-D", readOnly: True, 'hidePasswords': False}
                    - {'collection': CollectionObj, readOnly: True, 'hidePasswords': False}
        permissions permissions have no effect for now, only global setting
                    owner/admin/manager/user ditacte what the ACLs are.
        """
        (
            token,
            access_level,
            accessAll,
            permissions,
            remove,
            collections,
        ) = self._orga_args(
            token=token,
            access_level=access_level,
            accessAll=accessAll,
            remove=remove,
            sync=sync,
            collections=collections,
            permissions=permissions,
        )
        payloads = OrderedDict()
        orga = self.get_organization(orga, token=token, sync=sync)
        dcollections = self.collections_to_payloads(collections, orga=orga, token=token)
        for email in get_emails(emails_or_users):
            todo = False
            try:
                uacl = self.get_accesses({"user": email, "orga": orga})
            except NoAccessError:
                self.add_user_to_organization(
                    email,
                    orga,
                    collections=collections,
                    token=token,
                    sync=sync,
                    access_level=access_level,
                    permissions=permissions,
                    accessAll=accessAll,
                    readonly=readonly,
                    hidepasswords=hidepasswords,
                )
                uacl = self.get_accesses({"user": email, "orga": orga})
            uaccess = uacl["access"]
            ouid = uaccess["id"]
            todo = uaccess["type"] != access_level or uaccess["accessAll"] != accessAll
            # skip access setup for user which has accessAll set
            if uaccess["accessAll"] and not todo:
                L.debug(
                    f"{email} has already global access to collections, skip specific access setup"
                )
                continue
            payload = {
                "orga": orga,
                "email": email,
                "ouid": ouid,
                "removed": set(),
                "payload": {
                    "accessAll": accessAll,
                    "type": access_level,
                    "permissions": permissions,
                    "collections": deepcopy(uacl["acls"]),
                },
            }
            pid = ouid
            for cid, cdata in dcollections.items():
                collection = cdata["collection"]
                if collection.organizationId != orga.id:
                    L.debug(f"collection {collection.name} is not in orga: {orga.name}")
                    continue
                # set access on subsequent collections
                cremove = cdata.get("remove", remove)
                if cremove:
                    try:
                        uacl["daccess"][email][cid]
                    except KeyError:
                        L.info(
                            f"{email} has no access to collection {collection.name}/{collection.id}, no removal"
                        )
                    else:
                        L.info(f"Removing {cid} from {email} collections")
                        todo = True
                        payload["removed"].add(cid)
                        payload["payload"]["collections"] = list(
                            filter(
                                lambda a: a["id"] != cid,
                                payload["payload"]["collections"],
                            )
                        )
                else:
                    try:
                        caccess = uacl["daccess"][email]
                    except KeyError:
                        ro = bool(cdata.get("readOnly", readonly))
                        hp = bool(cdata.get("hidePasswords", hidepasswords))
                        L.info(
                            f"Adding {email} to collection {collection.name}/{collection.id}"
                        )
                        payload["payload"]["collections"].append(
                            {"id": cid, "hidePasswords": hp, "readOnly": ro}
                        )
                        todo = True
                    else:
                        if readonly is not None:
                            ro = readonly
                        else:
                            ro = caccess.get("readOnly", False)
                        if hidepasswords is not None:
                            hp = hidepasswords
                        else:
                            hp = caccess.get("hidePasswords", False)
                        ro = bool(cdata.get("readOnly", ro))
                        hp = bool(cdata.get("hidePasswords", hp))
                        aperm = [
                            a
                            for a in payload["payload"]["collections"]
                            if a["id"] == cid
                        ]
                        if aperm:
                            aperm = aperm[0]
                            if (aperm["readOnly"] == ro) and (
                                aperm["hidePasswords"] == hp
                            ):
                                log = f"Access In place {email}: collection {collection.name}/{collection.id}"
                            else:
                                log = f"Editing {email} access is in collection {collection.name}/{collection.id}"
                                aperm["readOnly"], aperm["hidePasswords"] = ro, hp
                                todo = True
                            L.info(log)
                        else:
                            raise BitwardenError(
                                "Acl mismatch for {email} in {orga.name}/{orga.id} / {collection.id}/{collection.name}"
                            )
            if todo:
                payloads[pid] = payload
        for ouid, cdata in payloads.items():
            orga = cdata["orga"]
            payload = cdata["payload"]
            ouid = cdata["ouid"]
            email = cdata["email"]
            L.debug(f"Setting accesses for {orga.name}/{orga.id}/{email}")
            u = f"/api/organizations/{orga.id}/users/{ouid}"
            resp = self.r(u, json=payload, method="put")
            self.assert_bw_response(resp)
            cdata["response"] = resp
        return payloads

    def compute_accesses(
        self, dcollections, remove=False, readonly=False, hidepasswords=False
    ):
        ret = {"payloads": [], "remove": []}
        for cid, col in (dcollections or {}).items():
            remove = col.get("remove", False)
            k = remove and "remove" or "payloads"
            ret[k].append(
                {
                    "id": col["collection"].id,
                    "hidePasswords": bool(col.get("hidepasswords", hidepasswords)),
                    "readOnly": bool(col.get("readOnly", readonly)),
                }
            )
        return ret

    def set_collection_access(
        self,
        emails_or_users,
        collections=None,
        readonly=False,
        hidepasswords=False,
        remove=None,
        orga=None,
        access_level=None,
        accessAll=False,
        permissions=None,
        token=None,
        sync=None,
    ):
        """
        Variant to create or update organization collections access at a COLLECTION level
        emails_or_users: email or Profile to set access to
        readonly: global readonly setting for the call if unset specifically for a collection
        remove: global readonly setting if user should be kicked/removed from the collection
        hidepasswords: global readonly setting for the call if unset specifically for a collection
        access_level (see bwclient.CollectionAccess for a readable enum: int for level access)
                (eg access_level=CollectionAccess.admin)
        collections: [list]
            items are  either:
                - collection
                - collectionId
                - a dict: {collection: col_or_id, [opt] readOnly: True/False, [opt] hidePasswords: True/False}
                - examples:
                    - Uu-ID-xx-xx
                    - Collection(...)
                    - {'collection': "U-U-I-D", readOnly: True, 'hidePasswords': False, remove: False}
                    - {'collection': CollectionObj, readOnly: True, 'hidePasswords': False, remove: False}
        orga (mostly never needed)
            Indeed, the only case where you can need it is when collections are selected via their name,
            orga should be set to select in the right orga.
        forwarded to add_user_to_organization call [if needed]
            access_level
            accessAll
            permissions
        """
        (
            token,
            access_level,
            accessAll,
            permissions,
            remove,
            collections,
        ) = self._orga_args(
            token=token,
            access_level=access_level,
            accessAll=accessAll,
            remove=remove,
            sync=sync,
            collections=collections,
            permissions=permissions,
        )
        if not (collections):
            raise BitwardenError("Choose collections to add to")
        dcollections = self.collections_to_payloads(collections, orga=orga, token=token)
        payloads = OrderedDict()
        for email in get_emails(emails_or_users):
            for cid, cdata in dcollections.items():
                collection = cdata["collection"]
                # check & add user to orga if needed
                orga = self.get_organization(collection.organizationId, token=token)
                oaccess = self.get_accesses(orga, token=token)
                try:
                    uid = oaccess["emails"][email]
                except KeyError:
                    self.add_user_to_organization(
                        email,
                        orga=orga,
                        accessAll=accessAll,
                        permissions=permissions,
                        token=token,
                    )
                    oaccess = self.get_accesses(orga, token=token)
                    uid = oaccess["emails"][email]
                # skip access setup for user which has accessAll set
                oacl = oaccess["daccess"][email]
                if oacl.get("accessAll", oacl.get("accessAll", False)):
                    L.debug(
                        f"{email} has already global access to collections, skip specific access setup"
                    )
                    continue
                access = self.get_accesses(collection, token=token)
                # set access on subsequent collections
                cremove = cdata.get("remove", remove)
                ro = bool(cdata.get("readOnly", readonly))
                hp = bool(cdata.get("hidePasswords", hidepasswords))
                acl = access["acls"]
                default_payload = {
                    "collection": collection,
                    "ro": ro,
                    "removed": set(),
                    "hp": hp,
                    "access": access,
                    "acl": acl,
                }
                if cremove:
                    try:
                        access["emails"][email]
                    except KeyError:
                        L.info(
                            f"{email} is not in collection {collection.name}/{collection.id}, no removal"
                        )
                    else:
                        L.info(
                            f"Removing {email} from collection {collection.name}/{collection.id}"
                        )
                        payload = payloads.setdefault(collection.id, default_payload)
                        payload["removed"].add(email)
                        acl = payload["acl"] = list(
                            filter(lambda a: a["id"] != uid, payload["acl"])
                        )
                else:
                    payload = payloads.get(collection.id, default_payload)
                    try:
                        access["emails"][email]
                    except KeyError:
                        L.info(
                            f"Adding {email} to collection {collection.name}/{collection.id}"
                        )
                        acl.append({"id": uid, "hidePasswords": hp, "readOnly": ro})
                        payloads[collection.id] = payload
                    else:
                        aperm = [a for a in acl if a["id"] == uid]
                        if aperm:
                            aperm = aperm[0]
                            if (aperm["readOnly"] == ro) and (
                                aperm["hidePasswords"] == hp
                            ):
                                log = f"Access In place {email}: collection {collection.name}/{collection.id}"
                            else:
                                log = f"Editing {email} access is in collection {collection.name}/{collection.id}"
                                aperm["readOnly"], aperm["hidePasswords"] = ro, hp
                                payloads[collection.id] = payload
                            L.info(log)
                        else:
                            raise BitwardenError(
                                "Acl mismatch for {email} in {collection.id}/{collection.name}"
                            )
        for c, cdata in payloads.items():
            c = cdata["collection"]
            payload = cdata["acl"]
            L.debug(f"Setting accesses for {c.name}/{c.id}")
            u = f"/api/organizations/{c.organizationId}/collections/{c.id}/users"
            resp = self.r(u, json=payload, method="put")
            self.assert_bw_response(resp)
            cdata["response"] = resp
        return payloads

    def collections_to_payloads(self, collections, orga=None, token=None):
        token = self.get_token(token)
        colexc = []
        dcollections = {}
        if collections:
            if isinstance(collections, (str, Collection)):
                collections = [collections]
            if not isinstance(collections, (str, list, tuple, set)):
                exc = BitwardenInvalidInput("collections is invalid")
                exc.inputs = [collections]
                raise exc
            colexc = BitwardenInvalidInput("collection item is invalid")
            colexc.inputs = []
            for i in collections:
                if isinstance(i, (str, Collection)):
                    data = {"collection": i}
                elif isinstance(i, dict):
                    data = i
                else:
                    colexc.inputs.append((i, orga))
                    continue
                col = data["collection"] = self.get_collection(
                    data["collection"], orga=orga, token=token
                )
                dcollections.setdefault(col.id, {}).update(data)
            if colexc.inputs:
                raise colexc
        return dcollections

    def ensure_private_key(self):
        if not self.private_key:
            raise BitwardenValidateError("no bitwarden server private key")

    def accept_invitation(self, orga, email, id=None, name=None, sync=None, token=None):
        self.ensure_private_key()
        token = self.get_token(token=token)
        orga = self.get_organization(orga, token=token)
        user = self.get_user(email=email, name=name, id=id, sync=sync)
        email = user.email
        oaccess = self.get_accesses(orga, token=token)
        try:
            acl = oaccess["daccess"][email]
        except KeyError:
            exc = InvitationAcceptError(f"{email} is not in organization {orga}")
            exc.orga, exc.email = orga, email
            raise exc
        else:
            # status: Invited = 0, Accepted = 1, Confirmed = 2,
            if acl["status"] != 0:
                exc = AlreadyInvitedError(
                    f"{email} is already accepted in organization {orga}"
                )
                exc.orga, exc.email = orga, email
                raise exc
        now = int(time())
        data = {
            "nbf": now,
            "exp": now + 432000,
            "iss": f"{self.server}|invite",
            "sub": user.id,
            "email": email,
            "org_id": orga.id,
            "user_org_id": acl["id"],
            "invited_by_email": self.email,
        }
        private_key = bwcrypto.load_rsa_key(self.private_key)
        pem_private_key = private_key.exportKey("PEM")
        jwt = jwt_encode(data, pem_private_key, algorithm="RS256")
        payload = {"userId": user.id, "token": jwt}
        try:
            u = f"/api/organizations/{orga.id}/users/{acl['id']}/accept"
            resp = self.r(u, json=payload, token=token)
            self.assert_bw_response(resp)
        except ResponseError as oexc:
            exc = PostInvitedError("invitation response failed")
            exc.email, exc.orga, exc.response = email, orga, oexc.response
            raise exc
        try:
            oaccess = self.get_accesses(orga, token=token)
            acl = oaccess["daccess"][email]
            assert acl["status"] != 0
        except AssertionError:
            exc = PostInvitedError("invitation did not complete")
            exc.email, exc.orga, exc.response = email, orga, resp
            raise exc
        L.info(
            f"Accepted user {user.email} / {user.name} / {user.id} in orga {orga.name} / {orga.id}"
        )
        return acl

    def confirm_invitation(self, orga, email, name=None, sync=None, token=None):
        """
        Just email is necessary to match users
        """
        token = self.get_token(token=token)
        orga = self.get_organization(orga, token=token)
        orgkey = self.get_organization_key(orga, token=token)
        oaccess = self.get_accesses(orga, token=token)
        try:
            acl = oaccess["daccess"][email]
        except KeyError:
            exc = ConfirmationAcceptError(
                f"{email} is not in organization {orga.name} / {orga.id}"
            )
            exc.orga, exc.email = orga, email
            raise exc
        else:
            # status: Confirmed = 0, Confirmed = 1, Confirmed = 2,
            if acl["status"] == 0:
                log = f"{email} is not yet accepted in organization {orga.name} / {orga.id}"
            elif acl["status"] == 2:
                log = f"{email} is already confirmed in organization {orga.name} / {orga.id}"
            else:
                log = ""
            if log:
                exc = AlreadyConfirmedError(log)
                exc.orga, exc.email = orga, email
                raise exc
        user_id = acl["userId"]
        resp = self.r(f"/api/users/{user_id}/public-key", method="get")
        self.assert_bw_response(resp)
        userorgkey = b64decode(resp.json()["PublicKey"])
        encoded_key = bwcrypto.encrypt_asym(orgkey[1], userorgkey)
        payload = {"Key": encoded_key}
        try:
            u = f"/api/organizations/{orga.id}/users/{acl['id']}/confirm"
            resp = self.r(u, json=payload, token=token)
            self.assert_bw_response(resp)
        except ResponseError as oexc:
            exc = PostConfirmedError("confirmation response failed")
            exc.email, exc.orga, exc.response = email, orga, oexc.response
            raise exc
        try:
            oaccess = self.get_accesses(orga, token=token)
            acl = oaccess["daccess"][email]
            assert acl["status"] == 2
        except AssertionError:
            exc = PostConfirmedError("confirmation did not complete")
            exc.email, exc.orga, exc.response = email, orga, resp
            raise exc
        L.info(f"Confirmed user {email} / {user_id} in orga {orga.name} / {orga.id}")
        return acl


def get_emails(emails_or_users):
    emails = []
    if not isinstance(emails_or_users, list):
        emails_or_users = [emails_or_users]
    for i in emails_or_users:
        if isinstance(i, Profile):
            i = i.email
        emails.append(i)
    return emails


# vim:set et sts=4 ts=4 tw=120:
