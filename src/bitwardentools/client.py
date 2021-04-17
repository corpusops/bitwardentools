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
import traceback
from base64 import b64decode, b64encode
from collections import OrderedDict
from copy import deepcopy
from secrets import token_bytes
from subprocess import run
from time import time

import requests
from jwt import encode as jwt_encode

from bitwardentools import crypto as bwcrypto
from bitwardentools.common import L

VAULTIER_FIELD_ID = "vaultiersecretid"
DEFAULT_CACHE = {"id": {}, "name": {}, "sync": False}
SECRET_CACHE = {"id": {}, "name": {}, "vaultier": {}, "sync": []}
CACHE = {
    "sync": {},
    "users": {},
    "okeys": {},
    "templates": {},
    "organizations": deepcopy(DEFAULT_CACHE),
    "collections": deepcopy(DEFAULT_CACHE),
    "ciphers": {
        "raw": {},
        "sync": False,
        "by_cipher": deepcopy(SECRET_CACHE),
        "by_collection": {},
        "by_organization": {},
    },
}

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
}


def pop_cache(cache):
    for i in [a for a in cache]:
        cache.pop(i, None)
    return cache


def uncapitzalize(s):
    if not s or not isinstance(s, str):
        return s
    return s[0].lower() + s[1:]


def clibase64(item):
    if not isinstance(item, str):
        item = json.dumps(item)
    enc = b64encode(item.encode()).replace(b"\n", b"")
    return enc.decode()


class BitwardenError(Exception):
    """."""


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


class NoSingleOrgaForNameError(BitwardenError):
    """."""

    instance = None


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


class Profile(BWFactory):
    """."""


class Organization(BWFactory):
    """."""

    def __init__(self, *a, **kw):
        ret = super(Organization, self).__init__(*a, *kw)
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


def get_all_cached_items(subcache):
    values = []
    for k in ("name",):
        for namevalue, items in subcache[k].items():
            values.append(items)
    for k in "id", "vaultier":
        try:
            values.append(subcache[k])
        except KeyError:
            pass
    return values


def get_reverse_cache():
    rciphers = get_all_cached_items(CACHE["ciphers"]["by_cipher"])
    for k in "by_collection", "by_organization":
        for container in CACHE["ciphers"][k]:
            rciphers.extend(get_all_cached_items(CACHE["ciphers"][k][container]))
    return {
        "organization": get_all_cached_items(CACHE["organizations"]),
        "collection": get_all_cached_items(CACHE["collections"]),
        "cipher": rciphers,
    }


def add_cipher(ret, obj, vaultier=False):
    ret["id"][str(obj.id)] = obj
    ret["name"].setdefault(obj.name, {})[obj.id] = obj
    if vaultier and getattr(obj, "vaultiersecretid", False):
        ret["vaultier"][str(obj.vaultiersecretid)] = obj


def cache_cipher(r, vaultier=True):
    scache = CACHE["ciphers"]
    scache["raw"][r.id] = r
    add_cipher(scache["by_cipher"], r, vaultier=vaultier)
    for cid in getattr(r, "collectionIds"):
        add_cipher(
            scache["by_collection"].setdefault(cid, deepcopy(SECRET_CACHE)),
            r,
            vaultier=vaultier,
        )
    for oid in [a for a in [getattr(r, "organizationId")] if a]:
        add_cipher(
            scache["by_organization"].setdefault(oid, deepcopy(SECRET_CACHE)),
            r,
            vaultier=vaultier,
        )


def cache_organization(r):
    CACHE["organizations"].setdefault("id", {})[r.id] = r
    CACHE["organizations"].setdefault("name", {}).setdefault(r.name, {})[r.id] = r


def cache_collection(r, scope="all"):
    if not isinstance(scope, dict):
        scope = CACHE["collections"].setdefault(scope, deepcopy(DEFAULT_CACHE))
    scope["id"][r.id] = r
    scope["name"][r.name] = r
    ex = scope.setdefault("externalId", {})
    if getattr(r, "externalId", None):
        ex[r.externalId] = r
    return scope


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
        vaultier=False,
    ):
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
        self.token = None
        if login:
            self.token = self.login()

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

    def r(self, uri, method="post", headers=None, token=None, *a, **kw):
        url = uri
        if not url.startswith("http"):
            url = f"{self.server}{uri}"
        if headers is None:
            headers = {}
        if token is not False:
            record = not token or not self.token
            token = token or self.token
            if not token:
                token = self.login()
            if record:
                self.token = token
            headers.update({"Authorization": f"Bearer {token['access_token']}"})
        resp = getattr(requests, method.lower())(url, headers=headers, *a, **kw)
        if resp.status_code in [401] and token is not False:
            L.debug(
                f"Access denied, trying to retry after refreshing token for {token['email']}"
            )
            ntoken = self.login(token["email"], token["password"])
            if record and (token is self.token):
                self.token = ntoken
            headers.update({"Authorization": f"Bearer {ntoken['access_token']}"})
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
        password = password or self.password
        data = self.r("/api/accounts/prelogin", json={"email": email}, token=False)
        jdata = data.json()
        iterations = jdata["KdfIterations"]
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
        token["iterations"] = iterations
        token["password"] = password
        token["hashed_password"] = hashed_password
        token["master_key"] = master_key
        token["email"] = email
        for k, f in {"Key": "user_key", "PrivateKey": "orgs_key"}.items():
            key = k != "PrivateKey" and master_key or token.get("user_key")
            token[f] = bwcrypto.decrypt(token[k], key)
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
            tpl = CACHE["templates"][otype]
        except KeyError:
            tpl = CACHE["templates"][otype] = self.call(f"get template {bwt}")
        tpl = deepcopy(tpl)
        tpl.update(kw)
        return tpl

    def api_sync(self, sync=None, cache=None, token=None):
        _CACHE = CACHE["sync"]
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
            cache_organization(orga)
        return orga

    def get_organizations(self, sync=None, cache=None, token=None):
        token = self.get_token(token)
        _CACHE = CACHE["organizations"]
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
                cache_organization(obj)
            _CACHE["sync"] = True
        return _CACHE

    def get_organization(self, orga, sync=None, cache=None, token=None, complete=None):
        token = self.get_token(token)
        if isinstance(orga, Organization):
            return orga
        _id = self.item_or_id(orga)
        try:
            return self.finish_orga(
                CACHE["organizations"]["id"][_id],
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
                exc.isntance = organizations
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
        if isinstance(obj, Collection):
            cache_method = cache_collection
        elif isinstance(obj, Organization):
            cache_method = cache_organization
        elif isinstance(obj, Item):
            cache_method = cache_cipher
        else:
            cache_method = None
        if cache_method:
            cache_method(obj)
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
        cache_organization(obj)
        return obj

    def create_organization(
        self,
        name,
        email,
        collection_name=None,
        collection_key=None,
        plan_type=0,
        token=None,
        **jsond,
    ):
        if collection_name is None:
            collection_name = f"C: {name}"
        if collection_key is None:
            collection_key = token_bytes(64)
        token = self.get_token(token)
        encoded_key = bwcrypto.encrypt_asym(collection_key, token["orgs_key"])
        encoded_collection_name = bwcrypto.encrypt_sym(collection_name, collection_key)
        data = {
            "key": encoded_key,
            "collectionName": encoded_collection_name,
            "name": name,
            "billingEmail": email or self.email,
            "planType": plan_type,
        }
        log = f'Creating organization {data["name"]}/'
        data.update(jsond)
        obj = self._upload_object(
            "/api/organizations", data, key=collection_key, log=log
        )
        cache_organization(obj)
        return obj

    def get_organization_key(self, orga, token=None, sync=None):
        if sync is None:
            sync = False
        if not isinstance(orga, Organization):
            orga = self.get_organization(orga, sync=sync)
        try:
            return CACHE["okeys"][orga.id]
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
                okey = bwcrypto.decrypt(enc_okey, token["orgs_key"])
                ret = CACHE["okeys"][orga.id] = enc_okey, okey
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
        cache_collection(obj)
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

    def get_collections(self, scope=None, sync=None, cache=None, token=None):
        """
        scope is either None for all or an orga(or orgaid)
        """
        token = self.get_token(token)
        if not scope:
            sync_key = "all"
        else:
            orga = self.get_organization(scope)
            sync_key = f"scope_{orga.id}"
        _CACHE = CACHE["collections"]
        if sync is None:
            sync = False
        if cache is None:
            cache = True
        if sync:
            _CACHE.pop("raw", None)
        if cache is False or sync:
            _CACHE.pop(sync_key, None)
            _CACHE.pop("all", None)
        try:
            return _CACHE[sync_key]
        except KeyError:
            pass
        #
        self.api_sync(sync=sync)
        #
        ret = deepcopy(DEFAULT_CACHE)
        try:
            ret = _CACHE["all"]
        except KeyError:
            for enccol in (
                self.r("/api/collections", method="get").json().get("Data", [])
            ):
                col = BWFactory.construct(enccol, client=self, unmarshall=True)
                _, colk = self.get_organization_key(col.organizationId, token=token)
                col.name = bwcrypto.decrypt(col.name, colk).decode()
                col.reflect()
                ret = cache_collection(col)
        #
        if scope:
            orga = self.get_organization(scope)
            for r in [
                col
                for col in _CACHE["all"]["id"].values()
                if col.organizationId == orga.id
            ]:
                ret = cache_collection(r, scope=sync_key)
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
        if isinstance(item_or_id_or_name, Collection):
            return item_or_id_or_name
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
        if _id:
            try:
                return collections["id"][_id]
            except KeyError:
                pass
            try:
                return collections["name"][_id]
            except KeyError:
                pass
        if externalId:
            try:
                return collections["externalId"][externalId]
            except KeyError:
                pass
        exc = CollectionNotFound(f"No such collection found {_id}/{externalId}")
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
        scache = CACHE["ciphers"]
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
                cache_cipher(obj, vaultier=vaultier)
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
        attachment_key = token_bytes(64)
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
            return item_or_id_or_name
        vaultier = self.get_vaultier(vaultier)
        token = self.get_token(token)
        _id = f"{self.item_or_id(item_or_id_or_name)}"
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
                ret = [s["vaultier"][_id]]
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

    def delete(self, obj, typ=None, token=None):
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
        self.uncache(typ=typ, _id=_id, obj=obj)
        ret = {}
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

    def uncache(self, typ=None, _id=None, obj=None):
        ids = set()
        assert typ or obj
        if isinstance(obj, BWFactory):
            objtyp = get_type(obj, typ)
            typ = TYPMAPPER.get(objtyp, "")
        typ = typ.lower()
        if _id:
            ids.add(_id)
        if obj:
            ids.add(obj.id)
        if typ == "organization":
            for u in ids:
                CACHE["okeys"].pop(u, None)
        caches = get_reverse_cache().get(typ, [])
        if ids and caches:
            for cache in caches:
                # cache.pop(id_, None)
                rcache = dict([(o.id, k) for k, o in cache.items()])
                try:
                    cache.pop(rcache[_id], None)
                except KeyError:
                    pass

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

    def get_users(self, sync=None):
        if sync is None:
            sync = False
        cache = CACHE["users"]
        if sync:
            pop_cache(cache)
        try:
            cache["emails"]
        except KeyError:
            emails = cache.setdefault("emails", OrderedDict())
            names = cache.setdefault("names", OrderedDict())
            ids = cache.setdefault("ids", OrderedDict())
            resp = self.adminr("/users", method="get")
            self.assert_bw_response(resp, expected_status_codes=[200, 500])
            if resp.status_code in [500]:
                pop_cache(cache)
                json = []
            else:
                json = resp.json()
            for user in json:
                obj = BWFactory.construct(user, client=self, unmarshall=True)
                emails[obj.email.lower()] = obj
                names[obj.name.lower()] = obj
                ids[obj.id.lower()] = obj
        return cache

    def get_user(self, email=None, name=None, id=None, user=None, sync=None):
        if isinstance(user, Profile):
            return user
        assert email or name or id
        cache = self.get_users(sync=sync)
        try:
            if not id:
                raise KeyError()
            return cache["ids"][id.lower()]
        except KeyError:
            try:
                if not email:
                    raise KeyError()
                return cache["emails"][email.lower()]
            except KeyError:
                try:
                    if not name:
                        raise KeyError()
                    return cache["names"][name.lower()]
                except KeyError:
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
            exc = ResponseError(str(orig_exc))
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

    def delete_user(self, email=None, name=None, id=None, user=None, sync=True):
        user = self.get_user(email=email, name=name, id=id, user=user, sync=sync)
        resp = self.adminr(f"/users/{user.id}/delete")
        self.post_user_request(resp)
        L.info(f"Deleted user {user.email} / {user.name} / {user.id}")
        return resp

    def validate(self, email, password=None, id=None, name=None, sync=None, token=None):
        token = self.get_token(token=token)
        if not self.private_key:
            exc = BitwardenValidateError("no bitwarden server private key")
            exc.email = email
            raise exc
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

    def warm(self, sync=True):
        ciphers = self.get_ciphers(sync=sync)
        orgas = self.get_organizations(sync=sync)
        collections = self.get_collections(sync=sync)
        return ciphers, collections, orgas


class AlreadyExitingUserError(RunError):
    """."""


# vim:set et sts=4 ts=4 tw=120:
