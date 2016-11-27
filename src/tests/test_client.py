#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import copy
import os
import unittest

from bitwardentools import client as bwclient
from bitwardentools import crypto as bwcrypto

ORGA_TEST_ID = os.environ.get("ORGA_TEST_ID", "bitwardentoolstest")
DSKIP = "daccess|emails|^id|^Id|userId|Object|ContinuationToken"
AL = bwclient.CollectionAccess


def strip_dict_data(data, skip=DSKIP):
    return bwclient.strip_dict_data(data, skip=skip)


class TestBitwardenInteg(unittest.TestCase):
    email = bwclient.EMAIL
    useremail = f"{bwclient.EMAIL}SIMPLE"
    password = bwclient.PASSWORD

    @classmethod
    def get_users(self):
        users = [("admin", self.email, self.password)]
        for i in ["", "delete"] + list(range(5)):
            users.append((f"user{i}", f"{self.useremail}{i}", self.password))
        return users

    @classmethod
    def wipe_objects(self):
        client = self.client
        for jsond in ({"object": "organization"},):
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

    def remove_from_orgacol(self):
        c = self.client
        for i in self.user1, self.user2, self.user3, self.user4:
            c.remove_user_from_organization(i[0], self.orgacol)

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
        orga1 = self.orga1 = client.create_organization(f"{ORGA_TEST_ID}1")
        orga2 = self.orga2 = client.create_organization(f"{ORGA_TEST_ID}2")
        orga3 = self.orga3 = client.create_organization(f"{ORGA_TEST_ID}3")
        orgacol = self.orgacol = client.create_organization(f"{ORGA_TEST_ID}COL")
        self.client.get_organization_key(orga)
        col = self.col = client.create_collection("bar", orga=orga.id)
        self.col1 = client.create_collection("bar1", orga=orga.id)
        self.col2 = client.create_collection("bar2", orga=orga.id)
        self.col3 = client.create_collection("bar3", orga=orga.id)
        self.col4 = client.create_collection("bar4", orga=orga.id)
        self.col5 = client.create_collection("bar5", orga=orga.id)
        self.col1_1 = client.create_collection("bar11", orga=orga1.id)
        self.col2_1 = client.create_collection("bar21", orga=orga2.id)
        self.col3_1 = client.create_collection("bar31", orga=orga3.id)
        self.colc = client.create_collection("colaccess", orga=orgacol.id)
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
        for ext in ["der", "pem"]:
            tpkey = f"/test/rsa_key.{ext}"
            private_key = bwclient.PRIVATE_KEY
            if os.path.exists(tpkey):
                with open(tpkey, "rb") as fic:
                    private_key = fic.read()
                break
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
        client.warm(sync=True)
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

        # be sure to get latest release of the cipher
        secitem = client.search_objects({"id": self.oseci.id}, sync=True)[0]
        n = secitem.notes
        ret = client.edit_item(secitem, notes="toosec")
        self.assertEqual(ret.notes, "toosec")
        ret = client.edit_item(ret, notes=n)
        item = client.search_objects({"id": secitem.id}, sync=True)[0]
        self.assertEqual(item.notes, n)

    def test_ciphers(self):
        client = self.client
        # Play with ciphers
        client.warm(sync=True)
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

    def test_logincache(self):
        self.client.login()
        token = self.client.login()
        self.assertTrue(token["_btw_login_count"] > 1)

    def test_bust(self):
        self.client.warm()
        test_cache = copy.deepcopy(self.client._cache)
        self.client.bust_cache()
        self.assertFalse(len(self.client._cache["users"]["id"]) > 0)
        self.assertTrue(len(test_cache["users"]["id"]) > 0)

    def test_add_user_to_organization(self):
        c = self.client
        c.add_user_to_organization(self.user[0], self.orga)
        c.add_user_to_organization(
            self.user1[0],
            self.orga1,
            collections=self.col1_1.id,
            access_level=AL.admin,
            readonly=True,
            hidepasswords=False,
        )
        c.add_user_to_organization(
            self.user1[0],
            self.orga2,
            access_level=AL.manager,
            collections=[self.col2_1.id],
        )
        c.add_user_to_organization(self.user1[0], self.orga3, collections=[self.col3_1])
        c.add_user_to_organization(self.user2[0], self.orga3, accessAll=True)
        c.add_user_to_organization(self.user3[0], self.orga3, accessAll=False)
        c.add_user_to_organization(self.user4[0], self.orga3)
        c.add_user_to_organization(
            self.user2[0],
            self.orga,
            collections=[
                self.col1.id,
                self.col2,
                {"collection": self.col3},
                {"collection": self.col4, "readOnly": True, "hidePasswords": True},
            ],
            hidepasswords=False,
            readonly=True,
        )
        c.add_user_to_organization(
            self.user3[0],
            self.orga,
            collections=[
                {"collection": self.col4, "readOnly": True, "hidePasswords": True},
            ],
            hidepasswords=False,
            readonly=True,
        )
        ###
        accesses = c.get_accesses(
            (
                self.orga,
                self.orga1,
                self.orga2,
                self.orga3,
                self.col1,
                self.col2,
                self.col3,
                self.col4,
                self.col1_1,
                self.col2_1,
                self.col3_1,
            )
        )
        saccesses = strip_dict_data(accesses)
        self.assertTrue(len(saccesses[self.orga.id]["acls"]))
        self.assertTrue(len(saccesses[self.orga1.id]["acls"]))
        self.assertTrue(len(saccesses[self.orga2.id]["acls"]))
        self.assertTrue(len(saccesses[self.orga3.id]["acls"]))
        #
        self.assertEqual(
            saccesses[self.col1.id]["acls"],
            [{"hidePasswords": False, "readOnly": True}],
        )
        self.assertEqual(
            saccesses[self.col2.id]["acls"],
            [{"hidePasswords": False, "readOnly": True}],
        )
        self.assertEqual(
            saccesses[self.col3.id]["acls"],
            [{"hidePasswords": False, "readOnly": True}],
        )
        self.assertEqual(
            saccesses[self.col1_1.id]["acls"],
            [{"hidePasswords": False, "readOnly": True}],
        )
        self.assertEqual(
            saccesses[self.col2_1.id]["acls"],
            [{"hidePasswords": False, "readOnly": False}],
        )
        self.assertEqual(
            saccesses[self.col3_1.id]["acls"],
            [{"hidePasswords": False, "readOnly": False}],
        )
        self.assertEqual(
            saccesses[self.col4.id]["acls"],
            [
                {"hidePasswords": False, "readOnly": True},
                {"hidePasswords": False, "readOnly": True},
            ],
        )
        #
        ekr = [a for a in sorted(accesses[self.orga.id]["emails"].keys())]
        ek = [a for a in sorted(accesses[self.orga.id]["emailsr"].values())]
        self.assertEqual(ek, ekr)
        self.assertEqual(
            ek,
            [
                "foo@org.com",
                "foo@org.comsimple",
                "foo@org.comsimple2",
                "foo@org.comsimple3",
            ],
        )
        self.assertEqual(
            list(sorted(accesses[self.col4.id]["emails"].keys())),
            ["foo@org.com", "foo@org.comsimple2", "foo@org.comsimple3"],
        )
        self.assertEqual(
            list(sorted(accesses[self.col4.id]["emailsr"].values())),
            ["foo@org.com", "foo@org.comsimple2", "foo@org.comsimple3"],
        )
        #
        self.assertEqual(
            strip_dict_data(list(accesses[self.col4.id]["daccessr"].values())),
            [
                {"hidePasswords": False, "readOnly": False},
                {"hidePasswords": False, "readOnly": True},
                {"hidePasswords": False, "readOnly": True},
            ],
        )
        self.assertEqual(
            strip_dict_data(list(accesses[self.col4.id]["daccess"].values())),
            [
                {"hidePasswords": False, "readOnly": False},
                {"hidePasswords": False, "readOnly": True},
                {"hidePasswords": False, "readOnly": True},
            ],
        )
        #
        self.assertEqual(
            list(
                sorted(strip_dict_data(list(accesses[self.col4.id]["daccess"].keys())))
            ),
            ["foo@org.com", "foo@org.comsimple2", "foo@org.comsimple3"],
        )
        self.assertEqual(
            list(
                sorted(strip_dict_data(list(accesses[self.col4.id]["daccessr"].keys())))
            ),
            list(sorted(accesses[self.col4.id]["emailsr"].keys())),
        )

    def test_remove_user_from_organization(self):
        c = self.client
        c.add_user_to_organization(self.user4[0], self.orgacol)
        self.assertRaises(
            bwclient.OrganizationNotFound,
            c.remove_user_from_organization,
            self.user4[0],
            "thiswontdoit",
        )
        ret1 = c.remove_user_from_organization(self.user4[0], self.orgacol)
        ret2 = c.remove_user_from_organization(self.user1[0], self.orgacol)
        self.assertEqual(ret1["foo@org.comsimple4"][self.orgacol.id].status_code, 200)
        self.assertEqual(ret2["foo@org.comsimple1"][self.orgacol.id], None)

    def test_remove_user_from_collection(self):
        c = self.client
        self.remove_from_orgacol()
        c.add_user_to_organization(self.user3[0], self.orgacol, collections=self.colc)
        self.assertRaises(
            bwclient.CollectionNotFound,
            c.remove_user_from_collection,
            self.user3[0],
            "thiswontdoit",
        )
        ret1 = c.remove_user_from_collection(self.user3[0], self.colc)
        ret3 = c.remove_user_from_collection(self.user3[0], self.colc)
        ret2 = c.remove_user_from_collection(self.user1[0], self.colc)
        self.assertEqual(ret1["foo@org.comsimple3"][self.colc.id].status_code, 200)
        self.assertEqual(ret3["foo@org.comsimple3"][self.colc.id], None)
        self.assertEqual(ret2["foo@org.comsimple1"][self.colc.id], None)

    def test_set_organization_access(self):
        c = self.client
        self.remove_from_orgacol()
        o = self.orgacol
        c.set_organization_access(self.user2[0], o, self.colc, hidepasswords=False)
        c.set_organization_access(self.user3[0], o, self.colc, hidepasswords=True)
        a0 = c.get_accesses(self.colc)
        self.assertTrue(a0["daccess"][self.user2[0].email]["hidePasswords"] is False)
        self.assertTrue(a0["daccess"][self.user3[0].email]["hidePasswords"] is True)
        self.assertEqual(len(strip_dict_data(a0["access"])), 2)
        #
        c.set_organization_access(
            self.user1[0], o, collections=self.colc, hidepasswords=False
        )
        a1a = c.get_accesses(self.colc)
        c.set_organization_access(
            self.user1[0], o, collections=self.colc, hidepasswords=True
        )
        a1b = c.get_accesses(self.colc)
        ao1 = c.get_accesses(self.orgacol)
        self.assertFalse(a1a["daccess"][self.user1[0].email]["hidePasswords"])
        self.assertTrue(a1b["daccess"][self.user1[0].email]["hidePasswords"])
        self.assertEqual(
            strip_dict_data(ao1["daccess"][self.user1[0].email]),
            {
                "accessAll": False,
                "email": "foo@org.comsimple1",
                "name": "fooatorgcomsimple1",
                "status": 0,
                "type": 2,
            },
        )
        #
        c.set_organization_access(
            self.user4[0],
            o,
            {"collection": self.colc, "hidePasswords": False},
            hidepasswords=True,
        )
        a2 = c.get_accesses(self.colc)
        self.assertFalse(a2["daccess"][self.user4[0].email]["hidePasswords"])
        self.assertRaises(
            bwclient.NoAccessError,
            c.get_accesses,
            {"user": self.user[0], "orga": self.orgacol},
        )
        ua2o = c.get_accesses({"user": self.user2[0], "orga": self.orgacol})
        ua3o = c.get_accesses({"user": self.user3[0], "orga": self.orgacol})
        self.assertEqual(self.user2[0].email, [a for a in ua2o["emails"].keys()][0])
        self.assertEqual(self.user3[0].email, [a for a in ua3o["emails"].keys()][0])
        ua2c = c.get_accesses({"user": self.user2[0], "collection": self.colc})
        ua3c = c.get_accesses({"user": self.user3[0], "collection": self.colc})
        self.assertEqual(self.user2[0].email, [a for a in ua2c["emails"].keys()][0])
        self.assertEqual(self.user3[0].email, [a for a in ua3c["emails"].keys()][0])
        #
        ar0b = c.get_accesses(self.colc)
        c.set_organization_access(self.user3[0], o, self.colc, remove=True)
        c.set_organization_access(
            self.user2[0], o, {"collection": self.colc, "remove": True}
        )
        ar0 = c.get_accesses(self.colc)
        self.assertEqual(
            list(sorted(ar0b["emails"])),
            [
                "foo@org.com",
                "foo@org.comsimple1",
                "foo@org.comsimple2",
                "foo@org.comsimple3",
                "foo@org.comsimple4",
            ],
        )
        self.assertEqual(
            list(sorted(ar0["emails"])),
            ["foo@org.com", "foo@org.comsimple1", "foo@org.comsimple4"],
        )

    def test_set_collection_access(self):
        c = self.client
        self.remove_from_orgacol()
        c.set_collection_access(self.user2[0], self.colc, hidepasswords=False)
        ret11 = c.set_collection_access(self.user3[0], self.colc, hidepasswords=True)
        a0 = c.get_accesses(self.colc)
        #
        c.set_collection_access(self.user3[0], self.colc, hidepasswords=False)
        c.set_collection_access(self.user3[0], self.colc, hidepasswords=False)
        a1 = c.get_accesses(self.colc)
        ao1 = c.get_accesses(self.orgacol)
        c.set_collection_access(
            self.user4[0],
            {"collection": self.colc, "hidePasswords": False},
            hidepasswords=True,
        )
        a2 = c.get_accesses(self.colc)
        ret4 = c.set_collection_access(self.user3[0], self.colc, remove=True)
        ret5 = c.set_collection_access(
            self.user2[0], {"collection": self.colc, "remove": True}
        )
        a3 = c.get_accesses(self.colc)
        self.assertEqual(
            [a for a in sorted([a for a in ao1["emails"]])],
            ["foo@org.com", "foo@org.comsimple2", "foo@org.comsimple3"],
        )
        self.assertFalse(self.user2[0].email not in a2["emails"])
        self.assertFalse(self.user3[0].email not in a2["emails"])
        self.assertTrue(self.user2[0].email not in a3["emails"])
        self.assertTrue(self.user3[0].email not in a3["emails"])
        self.assertEqual(
            strip_dict_data(a1["access"], skip="daccess|emails|Object|^id"),
            [
                {"hidePasswords": False, "readOnly": False},
                {"hidePasswords": False, "readOnly": False},
            ],
        )
        self.assertEqual(
            strip_dict_data(a2["access"], skip="daccess|emails|Object|^id"),
            [
                {"hidePasswords": False, "readOnly": False},
                {"hidePasswords": False, "readOnly": False},
                {"hidePasswords": False, "readOnly": False},
            ],
        )
        self.assertEqual(
            strip_dict_data(a3["access"], skip="daccess|emails|Object|^id"),
            [{"hidePasswords": False, "readOnly": False}],
        )
        self.assertEqual(
            [a for a in ret5.values()][0]["removed"], {"foo@org.comsimple2"}
        )
        self.assertEqual(
            [a for a in ret4.values()][0]["removed"], {"foo@org.comsimple3"}
        )
        self.assertTrue(ret11[self.colc.id]["hp"])
        self.assertFalse(ret11[self.colc.id]["ro"])
        self.assertFalse(a0["daccess"]["foo@org.comsimple2"]["hidePasswords"])
        self.assertTrue(a0["daccess"]["foo@org.comsimple3"]["hidePasswords"])


if __name__ == "__main__":
    unittest.main()
# vim:set et sts=4 ts=4 tw=120:
