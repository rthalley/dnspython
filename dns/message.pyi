# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from hmac import HMAC
from typing import Any, Dict, List, Optional, Tuple, Union

from dns.edns import Option
from dns.name import Name, IDNACodec
from dns.rcode import Rcode
from dns.rdataclass import IN
from dns.rdatatype import NONE
from dns.rrset import RRset
from dns.tsig import default_algorithm

class Message:
    def to_wire(self, origin : Optional[Name]=None, max_size: int = 0, **kw: Any) -> bytes:
        ...
    def find_rrset(self, section : List[RRset], name : Name, rdclass : int, rdtype : int,
                   covers: int = NONE, deleting : Optional[int]=None, create: bool = False,
                   force_unique: bool = False) -> RRset:
        ...
    def __init__(self, id : Optional[int] =None) -> None:
        self.id : int
        self.flags = 0
        self.question : List[RRset] = []
        self.answer : List[RRset] = []
        self.authority : List[RRset] = []
        self.additional : List[RRset] = []
        self.edns = -1
        self.ednsflags = 0
        self.payload = 0
        self.options : List[Option] = []
        self.sections : List[List[RRset]] = [[], [], [], []]
        self.opt : Optional[RRset] = None
        self.request_payload = 0
        self.keyring = None
        self.keyname = None
        self.keyalgorithm = default_algorithm
        self.tsig : Optional[RRset] = None
        self.request_mac = b''
        self.other_data = b''
        self.tsig_error = 0
        self.fudge = 300
        self.original_id = self.id
        self.mac = b''
        self.xfr = False
        self.origin = None
        self.tsig_ctx = None
        self.had_tsig = False
        self.multi = False
        self.first = True
        self.index : Dict[Tuple[RRset, Name, int, int, Union[int,str], int], RRset] = {}

    def is_response(self, other : Message) -> bool:
        ...

    def set_rcode(self, rcode : Rcode) -> None:
        ...

def from_text(a : str, idna_codec : Optional[IDNACodec] = None) -> Message:
    ...

def from_wire(wire: bytes, keyring : Optional[Dict[Name,bytes]] = None, request_mac: bytes = b'', xfr: bool = False, origin: Any = None,
              tsig_ctx : Optional[HMAC] = None, multi: bool = False, first: bool = True,
              question_only: bool = False, one_rr_per_rrset: bool = False,
              ignore_trailing: bool = False) -> Message:
    ...
def make_response(query : Message, recursion_available: bool = False, our_payload: int = 8192,
                  fudge: int = 300) -> Message:
    ...

def make_query(qname : Union[Name,str], rdtype : Union[str,int], rdclass : Union[int,str] =IN, use_edns : Optional[bool] = None,
               want_dnssec: bool = False, ednsflags : Optional[int] = None, payload : Optional[int] = None,
               request_payload : Optional[int] = None, options : Optional[List[Option]] = None) -> Message:
    ...
