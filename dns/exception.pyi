# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, Dict, Optional, Set

class DNSException(Exception):
    supp_kwargs : Set[str]
    kwargs : Optional[Dict[str, Any]]

class SyntaxError(DNSException): ...
class FormError(DNSException): ...
class Timeout(DNSException): ...
