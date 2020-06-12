# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license


from dns._asyncbackend import Socket, DatagramSocket, \
    StreamSocket, Backend, low_level_address_tuple  # noqa:


_default_backend = None
_trio_backend = None
_curio_backend = None
_asyncio_backend = None


def get_backend(name):
    """Get the specified asychronous backend.

    *name*, a ``str``, the name of the backend.  Currently the "trio",
    "curio", and "asyncio" backends are available.

    Raises NotImplementError if an unknown backend name is specified.
    """
    if name == 'trio':
        global _trio_backend
        if _trio_backend:
            return _trio_backend
        import dns._trio_backend
        _trio_backend = dns._trio_backend.Backend()
        return _trio_backend
    elif name == 'curio':
        global _curio_backend
        if _curio_backend:
            return _curio_backend
        import dns._curio_backend
        _curio_backend = dns._curio_backend.Backend()
        return _curio_backend
    elif name == 'asyncio':
        global _asyncio_backend
        if _asyncio_backend:
            return _asyncio_backend
        import dns._asyncio_backend
        _asyncio_backend = dns._asyncio_backend.Backend()
        return _asyncio_backend
    else:
        raise NotImplementedError(f'unimplemented async backend {name}')


def sniff():
    """Attempt to determine the in-use asynchronous I/O library by using
    the ``sniffio`` module if it is available.

    Returns the name of the library, defaulting to "asyncio" if no other
    library appears to be in use.
    """
    name = 'asyncio'
    try:
        import sniffio
        name = sniffio.current_async_library()
    except Exception:
        pass
    return name


def get_default_backend():
    """Get the default backend, initializing it if necessary.
    """
    if _default_backend:
        return _default_backend

    return set_default_backend(sniff())


def set_default_backend(name):
    """Set the default backend.

    It's not normally necessary to call this method, as
    ``get_default_backend()`` will initialize the backend
    appropriately in many cases.  If ``sniffio`` is not installed, or
    in testing situations, this function allows the backend to be set
    explicitly.
    """
    global _default_backend
    _default_backend = get_backend(name)
    return _default_backend
