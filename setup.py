# coding: utf-8
from setuptools import setup, find_packages  # noqa: H301

NAME = "presalytics-auth0-management-extensions"
VERSION = "0.1.4"

# To install the library, run the following
#
# python setup.py install
#
# prerequisite: setuptools
# http://pypi.python.org/pypi/setuptools

REQUIRES = [
    "auth0-python>=3.9.2",
    "environs>=7.4.0"
]

with open("README.md", "r") as fh:
    long_description = fh.read()
    

setup(
    name=NAME,
    version=VERSION,
    description="Presalytics Auth0 Management Extensions",
    author_email="inquiries@presalytics.io",
    url="https://presalytics.io/docs",
    keywords=["Presalytics", "Auth0"],
    install_requires=REQUIRES,
    packages=find_packages(),
    include_package_data=True,    
    long_description_content_type="text/markdown",
    long_description=long_description,

)
