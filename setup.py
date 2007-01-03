#!/usr/bin/env python

# Use --setuptools to use setuptools

import re
from os import path
import sys
if "--setuptools" in sys.argv:
    sys.argv.remove("--setuptools")
    from setuptools import setup
    use_setuptools = True
else:
    from distutils.core import setup
    use_setuptools = False

# Retrieve revision
regex_rev = re.compile(r"__revision__\s*=\s*[\"\'](.*)[\"\']\s*$", re.MULTILINE)
mod_file = open("pynetfilter_conntrack/__init__.py").read()
VERSION = regex_rev.search(mod_file).groups()[0]
print VERSION

DESCRIPTION = "pynetfilter_conntrack is a Python binding of libnetfilter_conntrack"
LONG_DESCRIPTION = open("README").read()
URL = "http://software.inl.fr/trac/trac.cgi/wiki/pynetfilter_conntrack"
KEYWORDS = "netfilter conntrack ctypes firewall"
REQUIRES = ("ctypes>=0.9.6", "IPy>=0.42")

CLASSIFIERS = filter(None, map(str.strip,
"""
Development Status :: 4 - Beta
Natural Language :: English
Environment :: Console
Intended Audience :: Developers
Intended Audience :: System Administrators
License :: OSI Approved :: GNU General Public License (GPL)
Operating System :: POSIX :: Linux
Programming Language :: Python
Topic :: Software Development :: Libraries :: Python Modules
Topic :: System :: Networking :: Firewalls
Topic :: System :: Networking :: Monitoring
""".splitlines()))

option = {}
if use_setuptools:
    option["zip_safe"] = True
    option["install_requires"] = REQUIRES

setup(
    name="pynetfilter_conntrack",
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    classifiers=CLASSIFIERS,
    author="Victor Stinner",
    author_email="victor.stinner AT inl.fr",
    url=URL,
    download_url=URL,
    license="GNU GPL",
    keywords=KEYWORDS,
    packages=["pynetfilter_conntrack"],
    platforms=['Linux'],
    package_dir={'pynetfilter_conntrack': 'pynetfilter_conntrack'},
    scripts=["conntrack.py"],
    **option
)

