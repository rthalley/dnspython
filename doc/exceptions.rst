.. _exceptions:

Exceptions
==========

Common Exceptions
-----------------

.. automodule:: dns.exception
   :members:

dns.name Exceptions
-------------------

.. autoexception:: dns.name.AbsoluteConcatenation
.. autoexception:: dns.name.BadEscape
.. autoexception:: dns.name.BadLabelType
.. autoexception:: dns.name.BadPointer
.. autoexception:: dns.name.EmptyLabel
.. autoexception:: dns.name.IDNAException
.. autoexception:: dns.name.LabelTooLong
.. autoexception:: dns.name.NameTooLong
.. autoexception:: dns.name.NeedAbsoluteNameOrOrigin
.. autoexception:: dns.name.NoIDNA2008
.. autoexception:: dns.name.NoParent

dns.rcode Exceptions
--------------------

.. autoexception:: dns.rcode.UnknownRcode

dns.rdataset Exceptions
-----------------------
                   
.. autoexception:: dns.rdataset.DifferingCovers
.. autoexception:: dns.rdataset.IncompatibleTypes
