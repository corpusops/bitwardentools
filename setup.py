#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
from setuptools import setup, find_packages


def read(*rnames):
    return open(os.path.join(".", *rnames)).read()


READMES = [
    a
    for a in [
        "README",
        "README.rst",
        "README.md",
        "README.txt",
        "CHANGES.md",
        "CHANGES.rst",
        "USAGE.rst",
        "USAGE.md",
        "HISTORY.md",
        "HISTORY.rst",
    ]
    if os.path.exists(a)
]
long_description = "\n\n".join([read(a) for a in READMES])
classifiers = ["Programming Language :: Python", "Topic :: Software Development"]
name = "bitwardentools"
version = "1.0.46"
src_dir = "src"
req = re.compile("^(?!(-e|#))", flags=re.I | re.M)
install_requires = [
    a.strip() for a in open("requirements/requirements.txt").read().splitlines() if req.search(a) and a.strip()
]
extra_requires = {}
candidates = {}
entry_points = {
    # z3c.autoinclude.plugin": ["target = plone"],
    # "console_scripts": ["foo = foo:main"],
}
setup(
    name=name,
    version=version,
    namespace_packages=[],
    description=name,
    long_description=long_description,
    classifiers=classifiers,
    keywords="",
    author="kiorky",
    author_email="kiorky@cryptelium.net",
    url="https://github.com/corpusops/bitwardentools",
    long_description_content_type='text/markdown',
    license="GPL",
    packages=find_packages(src_dir),
    package_dir={"": src_dir},
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extra_requires,
    entry_points=entry_points,
)
# vim:set ft=python:
