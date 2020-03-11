from typing import Optional, Union, Dict, Generator, Any
from . import tsig, rdatatype, rdataclass, name, message
from requests.sessions import Session

try:
    import ssl
except ImportError:
    class ssl(object):
        SSLContext = {}

def https(q : message.Message, where: str, timeout : Optional[float] = None, port : Optional[int] = 443, af : Optional[int] = None, source : Optional[str] = None, source_port : Optional[int] = 0,
          session: Optional[Session] = None, path : Optional[str] = '/dns-query', post : Optional[bool] = True, bootstrap_address : Optional[str] = None, verify : Optional[bool] = True) -> message.Message:
    pass

def tcp(q : message.Message, where : str, timeout : float = None, port=53, af : Optional[int] = None, source : Optional[str] = None, source_port : Optional[int] = 0,
        one_rr_per_rrset : Optional[bool] = False, ignore_trailing : Optional[bool] = False) -> message.Message:
    pass

def xfr(where : None, zone : Union[name.Name,str], rdtype=rdatatype.AXFR, rdclass=rdataclass.IN,
        timeout : Optional[float] =None, port=53, keyring : Optional[Dict[name.Name, bytes]] =None, keyname : Union[str,name.Name]=None, relativize=True,
        af : Optional[int] =None, lifetime : Optional[float]=None, source : Optional[str] =None, source_port=0, serial=0,
        use_udp : Optional[bool] = False, keyalgorithm=tsig.default_algorithm) -> Generator[Any,Any,message.Message]:
    pass

def udp(q : message.Message, where : str, timeout : Optional[float] = None, port=53, af : Optional[int] = None, source : Optional[str] = None, source_port : Optional[int] = 0,
        ignore_unexpected : Optional[bool] = False, one_rr_per_rrset : Optional[bool] = False, ignore_trailing : Optional[bool] = False) -> message.Message:
    pass

def tls(q : message.Message, where : str, timeout : Optional[float] = None, port=53, af : Optional[int] = None, source : Optional[str] = None, source_port : Optional[int] = 0,
        one_rr_per_rrset : Optional[bool] = False, ignore_trailing : Optional[bool] = False, ssl_context: Optional[ssl.SSLContext] = None, server_hostname: Optional[str] = None) -> message.Message:
    pass
