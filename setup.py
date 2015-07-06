#!/usr/bin/env python
# Installer: use --setuptools to use setuptools

from os import path
import sys
from imp import load_source
if "--setuptools" in sys.argv:
    sys.argv.remove("--setuptools")
    from setuptools import setup
    use_setuptools = True
else:
    from distutils.core import setup
    use_setuptools = False

# Retrieve revision
pynetfilter_conntrack = load_source("version", path.join("pynetfilter_conntrack", "version.py"))

DESCRIPTION = "pynetfilter_conntrack is a Python binding of libnetfilter_conntrack"
LONG_DESCRIPTION = open("README.rst").read() + open("INSTALL").read() + open("ChangeLog").read()
KEYWORDS = "netfilter conntrack ctypes firewall"
REQUIRES = ("ctypes>=0.9.6", "IPy>=0.50")

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
    name=pynetfilter_conntrack.PACKAGE,
    version=pynetfilter_conntrack.VERSION,
    url=pynetfilter_conntrack.WEBSITE,
    download_url=pynetfilter_conntrack.WEBSITE,
    license=pynetfilter_conntrack.LICENSE,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    classifiers=CLASSIFIERS,
    author="Victor Stinner",
    author_email="victor.stinner AT inl.fr",
    keywords=KEYWORDS,
    packages=["pynetfilter_conntrack"],
    platforms=['Linux'],
    package_dir={'pynetfilter_conntrack': 'pynetfilter_conntrack'},
    scripts=["conntrack.py"],
    **option
)

