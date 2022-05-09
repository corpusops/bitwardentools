#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import enum
import logging
import os
import re
from http.client import HTTPConnection


class VAULTIER_SECRET(enum.IntEnum):
    secret = 200
    note = 100
    file = 300


def sanitize(st):
    return st


def as_bool(value):
    if isinstance(value, str):
        return bool(re.match("^(y|o|1|t)", value.lower()))
    else:
        return bool(value)


CFG = os.environ.get("CONFIG", "/w/data/config.init")
EXPORT_DIR = os.environ.get("VAULTIER_EXPORT_DIR", "/w/data/export")
L = logging.getLogger("passwords")
LOGLEVEL = os.environ.get("LOGLEVEL", "info").upper()
REQUEST_DEBUG = as_bool(os.environ.get("REQUEST_DEBUG", ""))
_vars = {"debug": False}


def toggle_debug(activate=None, debuglevel=logging.DEBUG, errorlevel=logging.INFO):
    if activate is None:
        activate = not _vars["debug"]
    dl = debuglevel <= logging.DEBUG and 1 or 0
    lvl = activate and debuglevel or errorlevel
    HTTPConnection.debuglevel = dl
    req_log = logging.getLogger("requests.packages.urllib3")
    req_log.setLevel(lvl)
    req_log.propagate = activate
    _vars["debug"] = activate
    logging.getLogger("").setLevel(lvl)
    return activate


def setup_logging(loglevel=LOGLEVEL):
    logging.basicConfig(level=getattr(logging, loglevel))
    debuglvl = REQUEST_DEBUG and logging.DEBUG or logging.INFO
    toggle_debug(True, debuglevel=debuglvl)


# vim:set et sts=4 ts=4 tw=0:
