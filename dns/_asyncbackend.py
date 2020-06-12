# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import socket

import dns.inet


# This is a nullcontext for both sync and async

class NullContext:
    def __init__(self, enter_result=None):
        self.enter_result = enter_result

    def __enter__(self):
        return self.enter_result

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    async def __aenter__(self):
        return self.enter_result

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass


# This is handy, but should probably move somewhere else!

def low_level_address_tuple(af, high_level_address_tuple):
    address, port = high_level_address_tuple
    if af == dns.inet.AF_INET:
        return (address, port)
    elif af == dns.inet.AF_INET6:
        ai_flags = socket.AI_NUMERICHOST
        ((*_, tup), *_) = socket.getaddrinfo(address, port, flags=ai_flags)
        return tup
    else:
        raise NotImplementedError(f'unknown address family {af}')


# These are declared here so backends can import them without creating
# circular dependencies with dns.asyncbackend.

class Socket:
    async def close(self):
        pass

    async def __aenter__(self):
        pass

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()


class DatagramSocket(Socket):
    async def sendto(self, what, destination, timeout):
        pass

    async def recvfrom(self, size, timeout):
        pass


class StreamSocket(Socket):
    async def sendall(self, what, destination, timeout):
        pass

    async def recv(self, size, timeout):
        pass


class Backend:
    def name(self):
        return 'unknown'

    async def make_socket(self, af, socktype, proto=0,
                          source=None, raw_source=None,
                          ssl_context=None, server_hostname=None):
        raise NotImplementedError
