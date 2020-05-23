.. module:: dns.resolver
.. _resolver:

Stub Resolver
=============

Dnspython's resolver module implements a "stub resolver", which does DNS
recursion with the aid of a remote "full resolver" provided by an ISP
or other service provider.  By default, dnspython will use the full
resolver specifed by its host system, but another resolver can easily
be used simply by setting the *nameservers* attribute.

.. toctree::

   resolver-class
   resolver-functions
   resolver-caching
   resolver-override
