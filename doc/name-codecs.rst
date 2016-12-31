.. _name-codecs:

International Domain Name CODECs
--------------------------------

Representing non-ASCII text in the DNS is a complex and evolving
topic.  Generally speaking, Unicode is converted into an ASCII-only,
case-insensitive form called "Punycode" by complex rules.  There are
two standard specifications for this process, "IDNA 2003", which is
widely used, and the revised and not fully compatible standard "IDNA
2008".  There are also varying degrees of strictness that can be applied
in encoding and decoding.  Explaining the standards in detail is
out of scope for this document; Unicode Technical Standard #46
http://unicode.org/reports/tr46/ is a good place to start learning more.

Dnspython provides "codecs" to implement International Domain Name policy
according to the user's desire.

.. autoclass:: dns.name.IDNACodec
   :members:
.. autoclass:: dns.name.IDNA2003Codec
   :members:
.. autoclass:: dns.name.IDNA2008Codec
   :members:

.. data:: dns.name.IDNA_2003_Practical

   The "practical" codec encodes using IDNA 2003 rules and decodes
   punycode without checking for strict IDNA 2003 compliance.

.. data:: dns.name.IDNA_2003_Strict

   The "strict" codec encodes using IDNA 2003 rules and decodes
   punycode checking for IDNA 2003 compliance.

.. data:: dns.name.IDNA_2003

   A synonym for ``dns.name.IDNA_2003_Practical``.

.. data:: dns.name.IDNA_2008_Practical

   The "practical" codec encodes using IDNA 2008 rules with UTS 46
   compatibility processing, and allowing pure ASCII labels.  It
   decodes punycode without checking for strict IDNA 2008 compliance.

.. data:: dns.name.IDNA_2008_Strict

   The "strict" codec encodes using IDNA 2008 rules and decodes
   punycode checking for IDNA 2008 compliance.

.. data:: dns.name.IDNA_2008_UTS_46

   The "UTS 46" codec encodes using IDNA 2008 rules with UTS 46
   compatibility processing and decodes punycode without checking for
   IDNA 2008 compliance.

.. data:: dns.name.IDNA_2008_Transitional

   The "UTS 46" codec encodes using IDNA 2008 rules with UTS 46
   compatibility processing in the "transitional mode" and decodes
   punycode without checking for IDNA 2008 compliance.

.. data:: dns.name.IDNA_2008

   A synonym for ``dns.name.IDNA_2008_Practical``.
