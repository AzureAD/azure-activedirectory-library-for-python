.. ADAL Python documentation master file, created by
   sphinx-quickstart on Wed Apr 25 15:50:25 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. This file is also inspired by
   https://pythonhosted.org/an_example_pypi_project/sphinx.html#full-code-example

Welcome to ADAL Python's documentation!
=======================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

You can find high level conceptual documentations in the project
`wiki <https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki>`_
and
`workable samples inside the project code base
<https://github.com/AzureAD/azure-activedirectory-library-for-python/tree/dev/sample>`_

The documentation hosted here is for API Reference.


AuthenticationContext
=====================

The majority of ADAL Python functionalities are provided via the main class
named `AuthenticationContext`.

.. autoclass:: adal.AuthenticationContext
   :members:

   .. automethod:: __init__


TokenCache
==========

One of the parameter accepted by `AuthenticationContext` is the `TokenCache`.

.. autoclass:: adal.TokenCache
   :members:
   :undoc-members:

If you need to subclass it, you need to refer to its source code for the detail.


AdalError
=========

When errors are detected by ADAL Python, it will raise this exception.

.. autoclass:: adal.AdalError
   :members:

