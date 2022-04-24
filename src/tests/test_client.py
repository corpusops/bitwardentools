#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import os
import unittest

from bitwardentools import client as bwclient
from bitwardentools import crypto as bwcrypto


class TestBitwardenInteg(unittest.TestCase):
    email = bwclient.EMAIL
    useremail = f"{bwclient.EMAIL}SIMPLE"
    password = bwclient.PASSWORD

    def _wipe_objects(self):
        client = self.client
        for jsond in (
            #
            {"object": "organization", "name": "foo"},
            {"object": "organization", "name": "org"},
            {"object": "organization", "name": "testorgp"},
            {"object": "organization", "name": "bar"},
            #
            {"object": "collection", "name": "testcolp"},
            {"object": "collection", "name": "testcolp2"},
            #
            {"object": "item", "name": "testitp"},
            #
            {"object": "cipher", "name": "foo"},
            {"object": "cipher", "name": "secp"},
        ):
            objs = client.search(jsond)
            for obj in objs.values():
                try:
                    self.client.delete(obj)
                except bwclient.DeleteError:
                    pass

    def _wipe_users(self):
        for i in ["test@usr", "to@delete", bwclient.EMAIL]:
            try:
                self.delete_user(i)
            except Exception:
                pass

    def _wipe(self):
        self._wipe_objects()
        self._wipe_users()
        self._done = False

    def tearDown(self):
        self._wipe()

    def setUp(self):
        email, pw = self.email, self.password
        tpkey = "/test/rsa_key.der"
        private_key = bwclient.PRIVATE_KEY
        if os.path.exists(tpkey):
            with open(tpkey, "rb") as fic:
                private_key = fic.read()

        self.client = bwclient.Client(
            email=email, password=pw, private_key=private_key, login=False
        )
        for i in "foo", "org", "bar", "testorgp":
            try:
                self.client.get_organization(i)
                self._wipe_objects()
            except (bwclient.OrganizationNotFound, bwclient.LoginError):
                continue
            break
        self.setup_users()
        self._wipe()

    def setup_users(self):
        for attr, email, password in [
            ("admin", self.email, self.password),
            ("user", self.useremail, self.password),
        ]:
            try:
                self.client.delete_user(email)
            except (bwclient.UserNotFoundError):
                pass
            setattr(self, attr, self.client.create_user(email, password))
            if attr == "admin":
                self.client.login(email, password)

    def setup_fixtures(self):
        s, client = self, self.client
        if getattr(self, "_done", False):
            return
        orga = self.orga = client.create_organization("foo", "foo@foo.com")
        col = self.col = client.create_collection("bar", orga=orga.id)
        self.col2 = client.create_collection("bar2", orga=orga.id)
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
                "address1": "foo",
                "address2": "foo",
                "address3": "foo",
                "city": "foo",
                "postalCode": "foo",
                "country": "foo",
                "state": "foo",
                "username": "foo",
                "company": "foo",
                "phone": "foo",
                "email": "foo",
                "title": "Mrs",
                "firstName": "foo",
                "lastName": "foo",
                "middleName": "foo",
                "ssn": "foo",
                "licenseNumber": "foo",
                "passportNumber": "foo",
            },
            "notes": "foo",
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
                "cardholderName": "foo",
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
                "cardholderName": "foo",
                "number": "aaa",
                "code": "123456",
                "expMonth": "10",
                "expYear": "2013",
            },
            "fields": [{"name": "aaa", "type": 0, "value": "aaa"}],
            "notes": "aaa",
        }
        self.oseccard2 = client.create_card(
            "foo", orga, collections=[col], **self.seccard2
        )
        self.client.warm()
        self._done = True

    def test_create_via_payload(self):
        client = self.client
        orgp = {"object": "organization", "name": "testorgp", "email": "foo@org"}
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
        self.setup_fixtures()
        # Patch existing objects
        n = self.orga.name
        ret = client.edit_organization(self.orga, name="fooorg")
        item = client.search_objects({"id": self.orga.id}, sync=True)[0]
        self.assertEqual(ret.name, "fooorg")
        ret = client.edit_organization(self.orga, name=n)
        item = client.search_objects({"id": self.orga.id}, sync=True)[0]
        self.assertEqual(item.name, n)
        #
        n = self.col.name
        ret = client.edit_orgcollection(self.col, name="foocol")
        item = client.search_objects({"id": self.col.id}, sync=True)[0]
        self.assertEqual(ret.name, "foocol")
        ret = client.edit_orgcollection(self.col, name=n)
        item = client.search_objects({"id": self.col.id}, sync=True)[0]
        self.assertEqual(item.name, n)
        #
        n = self.oseci.notes
        ret = client.edit_item(self.oseci, notes="foosec")
        self.assertEqual(ret.notes, "foosec")
        ret = client.edit_item(self.oseci, notes=n)
        item = client.search_objects({"id": self.oseci.id}, sync=True)[0]
        self.assertEqual(item.notes, n)

    def test_ciphers(self):
        client = self.client
        self.setup_fixtures()
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
        email, pw = "test@usr", "12345657azertry"
        try:
            self.client.delete_user(email)
        except Exception:
            pass
        usr, epw = self.client.create_user(email, pw)
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

    def test_delete_user(self):
        uid = "to@delete"
        try:
            self.client.create_user(uid)
        except Exception:
            pass
        try:
            self.client.get_user(uid, sync=True)
        except bwclient.UserNotFoundError:
            self.assertTrue(False)
        self.client.delete_user(uid)
        self.assertRaises(
            bwclient.UserNotFoundError, self.client.get_user, uid, sync=True
        )


if __name__ == "__main__":
    unittest.main()
# vim:set et sts=4 ts=4 tw=120:
