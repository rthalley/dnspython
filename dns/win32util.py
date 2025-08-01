import os
import sys

import dns._features
import dns.name

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes as wintypes
    import winreg  # pylint: disable=import-error
    from enum import IntEnum
    from typing import Any

    import dns.name

    # Keep pylint quiet on non-windows.
    try:
        _ = WindowsError  # pylint: disable=used-before-assignment
    except NameError:
        WindowsError = Exception

    class ConfigMethod(IntEnum):
        Registry = 1
        WMI = 2
        Win32 = 3

    class DnsInfo:
        def __init__(self):
            self.domain = None
            self.nameservers = []
            self.search = []

    _config_method = ConfigMethod.Registry

    if dns._features.have("wmi"):
        import threading

        import pythoncom  # pylint: disable=import-error
        import wmi  # pylint: disable=import-error

        # Prefer WMI by default if wmi is installed.
        _config_method = ConfigMethod.WMI

        class _WMIGetter(threading.Thread):
            # pylint: disable=possibly-used-before-assignment
            def __init__(self):
                super().__init__()
                self.info = DnsInfo()

            def run(self):
                pythoncom.CoInitialize()
                try:
                    system = wmi.WMI()
                    for interface in system.Win32_NetworkAdapterConfiguration():
                        if interface.IPEnabled and interface.DNSServerSearchOrder:
                            self.info.nameservers = list(interface.DNSServerSearchOrder)
                            if interface.DNSDomain:
                                self.info.domain = _config_domain(interface.DNSDomain)
                            if interface.DNSDomainSuffixSearchOrder:
                                self.info.search = [
                                    _config_domain(x)
                                    for x in interface.DNSDomainSuffixSearchOrder
                                ]
                            break
                finally:
                    pythoncom.CoUninitialize()

            def get(self):
                # We always run in a separate thread to avoid any issues with
                # the COM threading model.
                self.start()
                self.join()
                return self.info

    else:

        class _WMIGetter:  # type: ignore
            pass

    def _config_domain(domain):
        # Sometimes DHCP servers add a '.' prefix to the default domain, and
        # Windows just stores such values in the registry (see #687).
        # Check for this and fix it.
        if domain.startswith("."):
            domain = domain[1:]
        return dns.name.from_text(domain)

    class _RegistryGetter:
        def __init__(self):
            self.info = DnsInfo()

        def _split(self, text):
            # The windows registry has used both " " and "," as a delimiter, and while
            # it is currently using "," in Windows 10 and later, updates can seemingly
            # leave a space in too, e.g. "a, b".  So we just convert all commas to
            # spaces, and use split() in its default configuration, which splits on
            # all whitespace and ignores empty strings.
            return text.replace(",", " ").split()

        def _config_nameservers(self, nameservers):
            for ns in self._split(nameservers):
                if ns not in self.info.nameservers:
                    self.info.nameservers.append(ns)

        def _config_search(self, search):
            for s in self._split(search):
                s = _config_domain(s)
                if s not in self.info.search:
                    self.info.search.append(s)

        def _config_fromkey(self, key, always_try_domain):
            try:
                servers, _ = winreg.QueryValueEx(key, "NameServer")
            except WindowsError:
                servers = None
            if servers:
                self._config_nameservers(servers)
            if servers or always_try_domain:
                try:
                    dom, _ = winreg.QueryValueEx(key, "Domain")
                    if dom:
                        self.info.domain = _config_domain(dom)
                except WindowsError:
                    pass
            else:
                try:
                    servers, _ = winreg.QueryValueEx(key, "DhcpNameServer")
                except WindowsError:
                    servers = None
                if servers:
                    self._config_nameservers(servers)
                    try:
                        dom, _ = winreg.QueryValueEx(key, "DhcpDomain")
                        if dom:
                            self.info.domain = _config_domain(dom)
                    except WindowsError:
                        pass
            try:
                search, _ = winreg.QueryValueEx(key, "SearchList")
            except WindowsError:
                search = None
            if search is None:
                try:
                    search, _ = winreg.QueryValueEx(key, "DhcpSearchList")
                except WindowsError:
                    search = None
            if search:
                self._config_search(search)

        def _is_nic_enabled(self, lm, guid):
            # Look in the Windows Registry to determine whether the network
            # interface corresponding to the given guid is enabled.
            #
            # (Code contributed by Paul Marks, thanks!)
            #
            try:
                # This hard-coded location seems to be consistent, at least
                # from Windows 2000 through Vista.
                connection_key = winreg.OpenKey(
                    lm,
                    r"SYSTEM\CurrentControlSet\Control\Network"
                    r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                    rf"\{guid}\Connection",
                )

                try:
                    # The PnpInstanceID points to a key inside Enum
                    (pnp_id, ttype) = winreg.QueryValueEx(
                        connection_key, "PnpInstanceID"
                    )

                    if ttype != winreg.REG_SZ:
                        raise ValueError  # pragma: no cover

                    device_key = winreg.OpenKey(
                        lm, rf"SYSTEM\CurrentControlSet\Enum\{pnp_id}"
                    )

                    try:
                        # Get ConfigFlags for this device
                        (flags, ttype) = winreg.QueryValueEx(device_key, "ConfigFlags")

                        if ttype != winreg.REG_DWORD:
                            raise ValueError  # pragma: no cover

                        # Based on experimentation, bit 0x1 indicates that the
                        # device is disabled.
                        #
                        # XXXRTH I suspect we really want to & with 0x03 so
                        # that CONFIGFLAGS_REMOVED devices are also ignored,
                        # but we're shifting to WMI as ConfigFlags is not
                        # supposed to be used.
                        return not flags & 0x1

                    finally:
                        device_key.Close()
                finally:
                    connection_key.Close()
            except Exception:  # pragma: no cover
                return False

        def get(self):
            """Extract resolver configuration from the Windows registry."""

            lm = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            try:
                tcp_params = winreg.OpenKey(
                    lm, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                )
                try:
                    self._config_fromkey(tcp_params, True)
                finally:
                    tcp_params.Close()
                interfaces = winreg.OpenKey(
                    lm,
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
                )
                try:
                    i = 0
                    while True:
                        try:
                            guid = winreg.EnumKey(interfaces, i)
                            i += 1
                            key = winreg.OpenKey(interfaces, guid)
                            try:
                                if not self._is_nic_enabled(lm, guid):
                                    continue
                                self._config_fromkey(key, False)
                            finally:
                                key.Close()
                        except OSError:
                            break
                finally:
                    interfaces.Close()
            finally:
                lm.Close()
            return self.info

    class _Win32Getter(_RegistryGetter):

        def get(self):
            """Get the attributes using the Windows API."""
            # Load the IP Helper library
            # # https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
            IPHLPAPI = ctypes.WinDLL("Iphlpapi.dll")

            # Constants
            AF_UNSPEC = 0
            ERROR_SUCCESS = 0
            GAA_FLAG_INCLUDE_PREFIX = 0x00000010
            AF_INET = 2
            AF_INET6 = 23
            IF_TYPE_SOFTWARE_LOOPBACK = 24

            # Define necessary structures
            class SOCKADDRV4(ctypes.Structure):
                _fields_ = [
                    ("sa_family", wintypes.USHORT),
                    ("sa_data", ctypes.c_ubyte * 14),
                ]

            class SOCKADDRV6(ctypes.Structure):
                _fields_ = [
                    ("sa_family", wintypes.USHORT),
                    ("sa_data", ctypes.c_ubyte * 26),
                ]

            class SOCKET_ADDRESS(ctypes.Structure):
                _fields_ = [
                    ("lpSockaddr", ctypes.POINTER(SOCKADDRV4)),
                    ("iSockaddrLength", wintypes.INT),
                ]

            class IP_ADAPTER_DNS_SERVER_ADDRESS(ctypes.Structure):
                pass  # Forward declaration

            IP_ADAPTER_DNS_SERVER_ADDRESS._fields_ = [
                ("Length", wintypes.ULONG),
                ("Reserved", wintypes.DWORD),
                ("Next", ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
                ("Address", SOCKET_ADDRESS),
            ]

            class IF_LUID(ctypes.Structure):
                _fields_ = [("Value", ctypes.c_ulonglong)]

            class NET_IF_NETWORK_GUID(ctypes.Structure):
                _fields_ = [("Value", ctypes.c_ubyte * 16)]

            class IP_ADAPTER_PREFIX_XP(ctypes.Structure):
                pass  # Left undefined here for simplicity

            class IP_ADAPTER_GATEWAY_ADDRESS_LH(ctypes.Structure):
                pass  # Left undefined here for simplicity

            class IP_ADAPTER_DNS_SUFFIX(ctypes.Structure):
                _fields_ = [
                    ("String", ctypes.c_wchar * 256),
                    ("Next", ctypes.POINTER(ctypes.c_void_p)),
                ]

            class IP_ADAPTER_UNICAST_ADDRESS_LH(ctypes.Structure):
                pass  # Left undefined here for simplicity

            class IP_ADAPTER_MULTICAST_ADDRESS_XP(ctypes.Structure):
                pass  # Left undefined here for simplicity

            class IP_ADAPTER_ANYCAST_ADDRESS_XP(ctypes.Structure):
                pass  # Left undefined here for simplicity

            class IP_ADAPTER_DNS_SERVER_ADDRESS_XP(ctypes.Structure):
                pass  # Left undefined here for simplicity

            class IP_ADAPTER_ADDRESSES(ctypes.Structure):
                pass  # Forward declaration

            IP_ADAPTER_ADDRESSES._fields_ = [
                ("Length", wintypes.ULONG),
                ("IfIndex", wintypes.DWORD),
                ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
                ("AdapterName", ctypes.c_char_p),
                ("FirstUnicastAddress", ctypes.POINTER(SOCKET_ADDRESS)),
                ("FirstAnycastAddress", ctypes.POINTER(SOCKET_ADDRESS)),
                ("FirstMulticastAddress", ctypes.POINTER(SOCKET_ADDRESS)),
                (
                    "FirstDnsServerAddress",
                    ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS),
                ),
                ("DnsSuffix", wintypes.LPWSTR),
                ("Description", wintypes.LPWSTR),
                ("FriendlyName", wintypes.LPWSTR),
                ("PhysicalAddress", ctypes.c_ubyte * 8),
                ("PhysicalAddressLength", wintypes.ULONG),
                ("Flags", wintypes.ULONG),
                ("Mtu", wintypes.ULONG),
                ("IfType", wintypes.ULONG),
                ("OperStatus", ctypes.c_uint),
                # Remaining fields removed for brevity
            ]

            def format_ipv4(sockaddr_in):
                return ".".join(map(str, sockaddr_in.sa_data[2:6]))

            def format_ipv6(sockaddr_in6):
                # The sa_data is:
                #
                # USHORT    sin6_port;
                # ULONG     sin6_flowinfo;
                # IN6_ADDR  sin6_addr;
                # ULONG     sin6_scope_id;
                #
                # which is 2 + 4 + 16 + 4 = 26 bytes, and we need the plus 6 below
                # to be in the sin6_addr range.
                parts = [
                    sockaddr_in6.sa_data[i + 6] << 8 | sockaddr_in6.sa_data[i + 6 + 1]
                    for i in range(0, 16, 2)
                ]
                return ":".join(f"{part:04x}" for part in parts)

            buffer_size = ctypes.c_ulong(15000)
            while True:
                buffer = ctypes.create_string_buffer(buffer_size.value)

                ret_val = IPHLPAPI.GetAdaptersAddresses(
                    AF_UNSPEC,
                    GAA_FLAG_INCLUDE_PREFIX,
                    None,
                    buffer,
                    ctypes.byref(buffer_size),
                )

                if ret_val == ERROR_SUCCESS:
                    break
                elif ret_val != 0x6F:  # ERROR_BUFFER_OVERFLOW
                    print(f"Error retrieving adapter information: {ret_val}")
                    return

            adapter_addresses = ctypes.cast(
                buffer, ctypes.POINTER(IP_ADAPTER_ADDRESSES)
            )

            current_adapter = adapter_addresses
            while current_adapter:

                # Skip non-operational adapters.
                oper_status = current_adapter.contents.OperStatus
                if oper_status != 1:
                    current_adapter = current_adapter.contents.Next
                    continue

                # Exclude loopback adapters.
                if current_adapter.contents.IfType == IF_TYPE_SOFTWARE_LOOPBACK:
                    current_adapter = current_adapter.contents.Next
                    continue

                # Get the domain from the DnsSuffix attribute.
                dns_suffix = current_adapter.contents.DnsSuffix
                if dns_suffix:
                    self.info.domain = dns.name.from_text(dns_suffix)

                current_dns_server = current_adapter.contents.FirstDnsServerAddress
                while current_dns_server:
                    sockaddr = current_dns_server.contents.Address.lpSockaddr
                    sockaddr_family = sockaddr.contents.sa_family

                    ip = None
                    if sockaddr_family == AF_INET:  # IPv4
                        ip = format_ipv4(sockaddr.contents)
                    elif sockaddr_family == AF_INET6:  # IPv6
                        sockaddr = ctypes.cast(sockaddr, ctypes.POINTER(SOCKADDRV6))
                        ip = format_ipv6(sockaddr.contents)

                    if ip:
                        if ip not in self.info.nameservers:
                            self.info.nameservers.append(ip)

                    current_dns_server = current_dns_server.contents.Next

                current_adapter = current_adapter.contents.Next

            # Use the registry getter to get the search info, since it is set at the system level.
            registry_getter = _RegistryGetter()
            info = registry_getter.get()
            self.info.search = info.search
            return self.info

    def set_config_method(method: ConfigMethod) -> None:
        global _config_method
        _config_method = method

    def get_dns_info() -> DnsInfo:
        """Extract resolver configuration."""
        if _config_method == ConfigMethod.Win32:
            getter = _Win32Getter()
        elif _config_method == ConfigMethod.WMI:
            getter = _WMIGetter()
        else:
            getter = _RegistryGetter()
        return getter.get()
