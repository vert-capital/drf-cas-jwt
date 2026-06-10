import sys

from setuptools import setup, find_packages

if sys.version_info < (3, 12):
    raise Exception("Only Python 3.12+ is supported")


setup(
    name="drf-cas-jwt",
    version="1.2.11",
    author="Caio de Faria",
    author_email="caio.faria@vert-capital.com",
    packages=find_packages(
        exclude=["ez_setup", "examples", "tests", "release"]
    ),
)
