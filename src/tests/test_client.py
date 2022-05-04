#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import copy
import os
import secrets
import unittest

from bitwardentools import client as bwclient
from bitwardentools import crypto as bwcrypto

ORGA_TEST_ID = os.environ.get("ORGA_TEST_ID", "bitwardentoolstest")


class TestBitwardenInteg(unittest.TestCase):
    email = bwclient.EMAIL
    useremail = f"{bwclient.EMAIL}SIMPLE"
    password = bwclient.PASSWORD

    @classmethod
    def get_users(self):
        users = [("admin", self.email, self.password)]
        for i in ["", "delete"] + list(range(4)):
            users.append((f"user{i}", f"{self.useremail}{i}", self.password))
        return users

    @classmethod
    def wipe_objects(self):
        client = self.client
        for jsond in (
            #
            {"object": "organization"},
            #
            {"object": "collection", "name": "toocol"},
            {"object": "collection", "name": "testcolp"},
            {"object": "collection", "name": "testcolp2"},
            #
            {"object": "item", "name": "testitp"},
            #
            {"object": "cipher", "name": "too"},
            {"object": "cipher", "name": "toosec"},
            {"object": "cipher", "name": "secp"},
        ):
            try:
                objs = client.search(jsond)
                if jsond["object"] == "organization":
                    objs = dict(
                        [
                            (a, objs[a])
                            for a in objs
                            if objs[a].name.startswith(ORGA_TEST_ID)
                        ]
                    )
            except bwclient.LoginError:
                # ADMIN seems not to exist now, bypass
                break
            for obj in objs.values():
                try:
                    self.client.delete(obj)
                except bwclient.DeleteError:
                    pass

    @classmethod
    def wipe_users(self):
        for attr, email, password in self.get_users():
            try:
                self.client.delete_user(email)
            except (bwclient.UserNotFoundError):
                pass

    @classmethod
    def wipe(self, wipe_users_first=False):
        methods = [self.wipe_objects, self.wipe_users]
        for m in wipe_users_first and reversed(methods) or methods:
            m()
        self.client.bust_cache()
        self._fixtures_done = False

    @classmethod
    def setup_users(self):
        for attr, email, password in self.get_users():
            setattr(self, attr, self.client.create_user(email, password))
        self.client.login(self.email, self.password)

    @classmethod
    def setup_fixtures(self):
        if getattr(self, "_fixtures_done", False):
            return
        s, client = self, self.client
        orga = self.orga = client.create_organization(ORGA_TEST_ID)
        self.client.get_organization_key(orga)
        col = self.col = client.create_collection("bar", orga=orga.id)
        self.col2 = client.create_collection("bar2", orga=orga.id)
        self.col3 = client.create_collection("bar3", orga=orga.id)
        self.col4 = client.create_collection("bar4", orga=orga.id)
        self.col5 = client.create_collection("bar5", orga=orga.id)
        self.secp = {
            "notes": "supernote",
            "login": {
                "totp": "aze",
                "username": "alice",
                "password": "rabbit",
                "uris": [{"match": None, "uri": "http://a"}],
            },
        }
        s.osec5 = client.create_item("sec5", orga, collections=[col], **self.secp)
        s.osecpersonal = client.create_item("secpersonal", **self.secp)
        self.seci = {
            "identity": {
                "address1": "too",
                "address2": "too",
                "address3": "too",
                "city": "too",
                "postalCode": "too",
                "country": "too",
                "state": "too",
                "username": "too",
                "company": "too",
                "phone": "too",
                "email": "too",
                "title": "Mrs",
                "firstName": "too",
                "lastName": "too",
                "middleName": "too",
                "ssn": "too",
                "licenseNumber": "too",
                "passportNumber": "too",
            },
            "notes": "too",
        }
        s.oseci = client.create_identity("sec1", orga, collections=[col], **self.seci)
        self.secn = {
            "fields": [{"name": "thisisabool", "type": 2, "value": False}],
            "notes": "notenote",
            "secureNote": {"type": 0},
        }
        self.osecn = client.create_securenote(
            "sec2", orga, collections=[col], **self.secn
        )
        self.seccard = {
            "card": {
                "brand": "sec",
                "cardholderName": "too",
                "number": "aaa",
                "code": "123456",
                "expMonth": "10",
                "expYear": "2013",
            },
            "fields": [{"name": "aaa", "type": 0, "value": "aaa"}],
            "notes": "aaa",
        }
        self.oseccard = client.create_card(
            "sec4", orga, collections=[col], **self.seccard
        )
        self.seccard2 = {
            "card": {
                "brand": "sec",
                "cardholderName": "too",
                "number": "aaa",
                "code": "123456",
                "expMonth": "10",
                "expYear": "2013",
            },
            "fields": [{"name": "aaa", "type": 0, "value": "aaa"}],
            "notes": "aaa",
        }
        self.oseccard2 = client.create_card(
            "too", orga, collections=[col], **self.seccard2
        )
        self.client.warm()
        self._fixtures_done = True

    @classmethod
    def tearDownClass(self):
        self.wipe()

    @classmethod
    def setUpClass(self):
        if getattr(self, "_setup_done", None):
            return
        tpkey = "/test/rsa_key.der"
        private_key = bwclient.PRIVATE_KEY
        if os.path.exists(tpkey):
            with open(tpkey, "rb") as fic:
                private_key = fic.read()
        self.client = bwclient.Client(
            email=self.email,
            password=self.password,
            private_key=private_key,
            login=False,
        )
        self.wipe()
        self.setup_users()
        self.setup_fixtures()
        self._setup_done = True

    def test_create_via_payload(self):
        client = self.client
        orgp = {
            "object": "organization",
            "name": f"{ORGA_TEST_ID}testorgp",
            "email": "too@org",
        }
        orga = client.create(**orgp)
        colp = {
            "object": "org-collection",
            "name": "testcolp",
            "organizationId": client.item_or_id(orga),
        }
        colp2 = {
            "object": "org-collection",
            "name": "testcolp2",
            "organizationId": client.item_or_id(orga),
        }
        col = client.create(**colp)
        col2 = client.create(**colp2)
        cipherp = {
            "object": "item",
            "name": "testitp",
            "organizationId": orga.id,
            "notes": "supernote",
            "login": {"username": "alice", "password": "rabbit"},
            "collectionIds": [col2.id],
        }
        cipher = client.create(**cipherp)
        for i in orga, col, col2, cipher:
            self.assertTrue(i, bwclient.BWFactory)
        for i in (
            lambda: (
                False
                not in [
                    colp2[a] == getattr(col2, a) for a in ["name", "organizationId"]
                ]
            ),
            lambda: (
                False
                not in [colp[a] == getattr(col, a) for a in ["name", "organizationId"]]
            ),
            lambda: (
                False
                not in [
                    cipherp[a] == getattr(cipher, a)
                    for a in ["name", "notes", "organizationId"]
                ]
            ),
            lambda: (
                False
                not in [
                    orgp[a] == getattr(orga, {"email": "billingEmail"}.get(a, a))
                    for a in ["name", "email"]
                ]
            ),
        ):
            self.assertTrue(i())

    def test_patch(self):
        client = self.client
        # Patch existing objects
        n = self.orga.name
        ret = client.edit_organization(self.orga, name="tooorg")
        item = client.search_objects({"id": self.orga.id}, sync=True)[0]
        self.assertEqual(ret.name, "tooorg")
        ret = client.edit_organization(self.orga, name=n)
        item = client.search_objects({"id": self.orga.id}, sync=True)[0]
        self.assertEqual(item.name, n)
        #
        n = self.col.name
        ret = client.edit_orgcollection(self.col, name="toocol")
        item = client.search_objects({"id": self.col.id}, sync=True)[0]
        self.assertEqual(ret.name, "toocol")
        ret = client.edit_orgcollection(self.col, name=n)
        item = client.search_objects({"id": self.col.id}, sync=True)[0]
        self.assertEqual(item.name, n)
        #
        n = self.oseci.notes
        ret = client.edit_item(self.oseci, notes="toosec")
        self.assertEqual(ret.notes, "toosec")
        ret = client.edit_item(self.oseci, notes=n)
        item = client.search_objects({"id": self.oseci.id}, sync=True)[0]
        self.assertEqual(item.notes, n)

    def test_ciphers(self):
        client = self.client
        # Play with ciphers
        all_ciphers = client.get_ciphers(collection=self.col)
        cipher = [a for a in all_ciphers["id"].values()][0]
        # Put cipther in collection col2
        ret = client.link(cipher, self.col2)
        itms = client.search_objects({"id": cipher.id}, sync=True)
        self.assertEqual(ret[0].id, self.col2.id)
        ids = itms[0].collectionIds
        self.assertEqual(len(ids), 2)
        self.assertTrue(self.col2.id in ids)
        ret = client.unlink(cipher, self.col2)
        itms = client.search_objects({"id": cipher.id}, sync=True)
        self.assertFalse(self.col2.id in itms[0].collectionIds)
        # login
        for i in (
            lambda: self.secp["login"]["uris"][0]["uri"]
            == self.osec5.login["uris"][0]["uri"],
            lambda: self.secp["notes"] == self.osec5.notes,
            lambda: (
                False
                not in [
                    (self.osec5.login[i] == self.secp["login"][i])
                    for i in ["totp", "username", "password"]
                ]
            ),
        ):
            self.assertTrue(i())
        # note
        for i in (
            lambda: (
                False not in [self.secn[a] == getattr(self.osecn, a) for a in ["notes"]]
            ),
            lambda: (
                False
                not in [
                    (self.osecn.secureNote[i] == self.secn["secureNote"][i])
                    for i in ["type"]
                ]
            ),
        ):
            self.assertTrue(i())
        # seccard
        for i in (
            lambda: (
                {"name": "aaa", "type": 0, "value": "aaa"} == self.oseccard.fields[0]
            ),
            lambda: (
                False
                not in [self.seccard[a] == getattr(self.oseccard, a) for a in ["notes"]]
            ),
            lambda: (
                False
                not in [
                    (self.oseccard.card[i] == self.seccard["card"][i])
                    for i in ["brand", "cardholderName", "code"]
                ]
            ),
        ):
            self.assertTrue(i())
        # id
        for i in (
            lambda: (
                False not in [self.seci[a] == getattr(self.oseci, a) for a in ["notes"]]
            ),
            lambda: (
                False
                not in [
                    (self.oseci.identity[i] == self.seci["identity"][i])
                    for i in ["title", "address3", "company"]
                ]
            ),
        ):
            self.assertTrue(i())

    def test_create_user(self):
        email, pw = self.email, self.password
        usr, epw = self.admin
        self.assertEqual(email, usr.email)
        self.assertEqual(pw, epw)
        self.assertTrue(usr.emailVerified)
        self.assertRegex(usr.privateKey, bwcrypto.SYM_ENCRYPTED_STRING_RE)
        self.assertRegex(usr.key, bwcrypto.SYM_ENCRYPTED_STRING_RE)
        key = bwcrypto.decrypt(usr.key, bwcrypto.make_master_key(pw, usr.email))
        rsak = bwcrypto.load_rsa_key(bwcrypto.decrypt(usr.privateKey, key))
        self.assertTrue(
            rsak.public_key().exportKey("PEM").decode(), "-----BEGIN PUBLIC KEY-----"
        )

    def test_uncache1(self):
        c1 = copy.deepcopy(self.client._cache)
        self.client.uncache(obj=self.admin[0])
        c2 = copy.deepcopy(self.client._cache)
        self.assertEqual(len(c1["users"]["id"]) - 1, len(c2["users"]["id"]))
        self.assertFalse(self.admin[0].id in c2["users"]["id"])
        self.assertTrue(self.admin[0].id in c1["users"]["id"])
        self.assertFalse(self.admin[0].email in c2["users"]["email"])
        self.assertTrue(self.admin[0].email in c1["users"]["email"])
        self.client.cache(self.admin[0])
        c3 = copy.deepcopy(self.client._cache)
        self.assertTrue(self.admin[0].id in c3["users"]["id"])
        self.assertTrue(self.admin[0].email in c3["users"]["email"])

    def test_delete_user(self):
        uid = self.userdelete[0]
        self.client.delete_user(user=uid)
        self.assertRaises(
            bwclient.UserNotFoundError, self.client.get_user, user=uid, sync=True
        )

    def test_bust(self):
        self.client.warm()
        test_cache = copy.deepcopy(self.client._cache)
        self.client.bust_cache()
        self.assertFalse(len(self.client._cache["users"]["id"]) > 0)
        self.assertTrue(len(test_cache["users"]["id"]) > 0)


if __name__ == "__main__":
    unittest.main()
# vim:set et sts=4 ts=4 tw=120:
