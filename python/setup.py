#!/usr/bin/env python3
from distutils.core import setup
import r2pipe

# with open('README.rst') as readme_file:
#    readme = readme_file.read()

setup(
    name="r2pipe",
    version=r2pipe.version(),
    license="MIT",
    description="Pipe interface for radare2",
    author="pancake",
    author_email="pancake@nopcode.org",
    url="https://rada.re",
    package_dir={"r2pipe": "r2pipe"},
    packages=["r2pipe"],
)
