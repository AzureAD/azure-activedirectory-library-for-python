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
    description='TODO',
    license='TODO',
    author='TODO',
    author_email='TODO',
    url='https://github.com/AzureAD/azure-activedirectory-library-for-python-priv',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'License :: OSI Approved :: TODO',
    ],
    packages=['adal'],
    install_requires=[
        'PyJWT',
        'requests',
    ]
)
