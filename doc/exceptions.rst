.. _exceptions:

Exceptions
==========

Common Exceptions
-----------------

.. automodule:: dns.exception
   :members:

dns.dnssec Exceptions
---------------------

.. autoexception:: dns.dnssec.UnsupportedAlgorithm
.. autoexception:: dns.dnssec.ValidationFailure

      
dns.message Exceptions
----------------------

.. autoexception:: dns.message.BadEDNS
.. autoexception:: dns.message.BadTSIG
.. autoexception:: dns.message.ShortHeader
.. autoexception:: dns.message.TrailingJunk
.. autoexception:: dns.message.UnknownHeaderField
.. autoexception:: dns.message.UnknownTSIGKey

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

dns.opcode Exceptions
---------------------

.. autoexception:: dns.opcode.UnknownOpcode

dns.query Exceptions
--------------------

.. autoexception:: dns.query.BadResponse
.. autoexception:: dns.query.NoDOH
.. autoexception:: dns.query.UnexpectedSource
.. autoexception:: dns.query.TransferError


dns.rcode Exceptions
--------------------

.. autoexception:: dns.rcode.UnknownRcode

dns.rdataset Exceptions
-----------------------
                   
.. autoexception:: dns.rdataset.DifferingCovers
.. autoexception:: dns.rdataset.IncompatibleTypes

dns.resolver Exceptions
-----------------------

.. autoexception:: dns.resolver.NoAnswer
.. autoexception:: dns.resolver.NoMetaqueries
.. autoexception:: dns.resolver.NoNameservers
.. autoexception:: dns.resolver.NoRootSOA
.. autoexception:: dns.resolver.NotAbsolute
.. autoexception:: dns.resolver.NXDOMAIN
.. autoexception:: dns.resolver.YXDOMAIN

dns.tokenizer Exceptions
------------------------

.. autoexception:: dns.tokenizer.UngetBufferFull

dns.ttl Exceptions
------------------

.. autoexception:: dns.ttl.BadTTL

dns.zone Exceptions
-------------------

.. autoexception:: dns.zone.BadZone
.. autoexception:: dns.zone.NoSOA
.. autoexception:: dns.zone.NoNS
.. autoexception:: dns.zone.UnknownOrigin
