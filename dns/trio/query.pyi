!from typing import Optional, Union, Dict, Generator, Any
from . import tsig, rdatatype, rdataclass, name, message
from requests.sessions import Session

# If the ssl import works, then
#
#    error: Name 'ssl' already defined (by an import)
#
# is expected and can be ignored.
try:
    import ssl
except ImportError:
    class ssl(object):    # type: ignore
        SSLContext : Dict = {}

def udp(q : message.Message, where : str, port=53,
        source : Optional[str] = None, source_port : Optional[int] = 0,
        ignore_unexpected : Optional[bool] = False,
        one_rr_per_rrset : Optional[bool] = False,
        ignore_trailing : Optional[bool] = False) -> message.Message:
    ...

def stream(q : message.Message, where : str, tls : Optional[bool] = False,
           port=53, source : Optional[str] = None,
           source_port : Optional[int] = 0,
           one_rr_per_rrset : Optional[bool] = False,
           ignore_trailing : Optional[bool] = False,
           ssl_context: Optional[ssl.SSLContext] = None,
           server_hostname: Optional[str] = None) -> message.Message:
    ...
