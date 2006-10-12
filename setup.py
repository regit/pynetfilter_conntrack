#!/usr/bin/env python

try:
    from setuptools import setup
    use_setuptools = True
except ImportError:
    from distutils.core import setup
    use_setuptools = False

VERSION = '0.1'
DESCRIPTION = "pynetfilter_conntrack is a Python binding of libnetfilter_conntrack"
LONG_DESCRIPTION = open("README").read()

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

setup(
    name="pynetfilter_conntrack",
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    classifiers=CLASSIFIERS,
    author="Victor Stinner",
    author_email="victor.stinner AT inl.fr",
    url="http://software.inl.fr/trac/trac.cgi/wiki/pynetfilter_conntrack",
    license="GNU GPL",
    packages=["pynetfilter_conntrack"],
    platforms=['Linux'],
    package_dir={'pynetfilter_conntrack': 'pynetfilter_conntrack'},
    scripts=["conntrack.py"],
    **option
)

