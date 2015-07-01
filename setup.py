#!/usr/bin/env python

from setuptools import setup

# To build:
# python setup.py sdist
# python setup.py bdist_wheel
#
# To install:
# python setup.py install
#
# To register (only needed once):
# python setup.py register
#
# To upload:
# python setup.py sdist upload
# python setup.py bdist_wheel upload

setup(
    name='adal',
    version='0.1.0',
    description='The ADAL for Python library makes it easy for python application to authenticate to Azure Active Directory (AAD) in order to access AAD protected web resources.',
    license='Apache 2',
    author='Microsoft Open Technologies Inc',
    author_email='msopentech@microsoft.com',
    url='https://github.com/AzureAD/azure-activedirectory-library-for-python-priv',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'License :: OSI Approved :: MIT License',  'License :: OSI Approved :: Apache Software License'
    ],
    packages=['adal'],
    install_requires=[
        'PyJWT',
        'requests',
    ]
)
