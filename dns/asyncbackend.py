# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license


from dns._asyncbackend import Socket, DatagramSocket, \
    StreamSocket, Backend, low_level_address_tuple


_default_backend = None


def get_default_backend():
    if _default_backend:
        return _default_backend

    return set_default_backend(sniff())


def sniff():
    name = 'asyncio'
    try:
        import sniffio
        name = sniffio.current_async_library()
    except Exception:
        pass
    return name


def set_default_backend(name):
    global _default_backend

    if name == 'trio':
        import dns._trio_backend
        _default_backend = dns._trio_backend.Backend()
    elif name == 'curio':
        import dns._curio_backend
        _default_backend = dns._curio_backend.Backend()
    elif name == 'asyncio':
        import dns._asyncio_backend
        _default_backend = dns._asyncio_backend.Backend()
    else:
        raise NotImplementedException(f'unimplemented async backend {name}')

    return _default_backend
