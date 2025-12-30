import socket
from typing import Awaitable, Callable, Never

import dns.asyncbackend
import dns.asyncquery
import dns.exception
import dns.inet
import dns.message
import dns.name
import dns.rcode
import dns.tsig


def _rcode_from_exception(e: Exception) -> dns.rcode.Rcode:
    """Get rcode for exception"""
    if isinstance(e, dns.exception.FormError):
        return dns.rcode.FORMERR
    elif isinstance(e, dns.exception.SyntaxError):
        return dns.rcode.SERVFAIL
    elif isinstance(e, dns.exception.UnexpectedEnd):
        return dns.rcode.BADTRUNC
    elif isinstance(e, dns.exception.TooBig):
        return dns.rcode.BADTRUNC
    elif isinstance(e, dns.exception.Timeout):
        return dns.rcode.SERVFAIL
    elif isinstance(e, dns.exception.UnsupportedAlgorithm):
        return dns.rcode.BADALG
    elif isinstance(e, dns.exception.AlgorithmKeyMismatch):
        return dns.rcode.BADALG
    elif isinstance(e, dns.exception.ValidationFailure):
        return dns.rcode.SERVFAIL
    elif isinstance(e, dns.exception.DeniedByPolicy):
        return dns.rcode.REFUSED
    elif isinstance(e, NotImplementedError):
        return dns.rcode.NOTIMP
    return dns.rcode.SERVFAIL


async def udp_serve(
    cb: Callable[[dns.message.Message, str], Awaitable[dns.message.Message]],
    host: str,
    port: int = 53,
    keyring: dict[dns.name.Name, dns.tsig.Key] | None = None,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    ignore_errors: bool = False,
    backend: dns.asyncbackend.Backend | None = None,
) -> None:
    if not backend:
        backend = dns.asyncbackend.get_default_backend()
    af = dns.inet.af_for_address(host)
    addr = (host, port)
    sock = await backend.make_socket(af, socket.SOCK_DGRAM, 0, addr)
    while True:
        try:
            (m, _, from_address) = await dns.asyncquery.receive_udp(
                sock,
                one_rr_per_rrset=one_rr_per_rrset,
                keyring=keyring,
                ignore_trailing=ignore_trailing,
                ignore_errors=ignore_errors,
            )
            try:
                r = await cb(m, from_address)
            except Exception as e:
                r = dns.message.make_response(m)
                r.set_rcode(_rcode_from_exception(e))
            wire = r.to_wire()
            await dns.asyncquery.send_udp(sock, wire, from_address)
        except:
            pass


async def tcp_serve(
    cb: Callable[[dns.message.Message, str], Awaitable[dns.message.Message]],
    host: str,
    port: int = 53,
    keyring: dict[dns.name.Name, dns.tsig.Key] | None = None,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    ignore_errors: bool = False,
    backend: dns.asyncbackend.Backend | None = None,
) -> None:
    async def handle_tcp(sock: dns.asyncbackend.StreamSocket):
        peer_address = await sock.getpeername()
        while True:
            try:
                (m, _) = await dns.asyncquery.receive_tcp(
                    sock,
                    one_rr_per_rrset=one_rr_per_rrset,
                    keyring=keyring,
                    ignore_trailing=ignore_trailing,
                    ignore_errors=ignore_errors,
                )
                try:
                    r = await cb(m, peer_address)
                except Exception as e:
                    r = dns.message.make_response(m)
                    r.set_rcode(_rcode_from_exception(e))
                wire = r.to_wire()
                await dns.asyncquery.send_tcp(sock, wire)
            except EOFError:
                return
            except:
                continue

    if not backend:
        backend = dns.asyncbackend.get_default_backend()
    af = dns.inet.af_for_address(host)
    addr = (host, port)
    server = await backend.make_server(handle_tcp, af, socket.SOCK_STREAM, addr)
    await server.serve_forever()
