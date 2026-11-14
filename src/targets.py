import fqdn
import pydantic
import rich.panel

import ipaddress
import sys
import typing
import urllib.parse

import verbose


class Targeter(pydantic.BaseModel):
    """Parses the `targets` stores them in different kind of formats."""

    ipv4s: list[str] = []
    ipv4s_with_port: list[str] = []
    ipv6s: list[str] = []
    ipv6s_with_port: list[str] = []
    fqdns: list[str] = []
    fqdns_with_port: list[str] = []
    cidrs_v4: list[str] = []
    cidrs_v6: list[str] = []
    urls: list[str] = []
    invalids: list[str] = []

    def parse_targets_file(self, targets_filepath: str) -> None:
        """
        Parses the targets from a text file or stdin ("-").

        Args:
            targets_filepath (str): Path to file or "-" to read from stdin.

        """
        if targets_filepath == '-':
            self._add_targets(sys.stdin)
        else:
            with open(targets_filepath, 'r', encoding='utf-8') as f:
                self._add_targets(f)

    def parse_targets_str(self, targets_str: str) -> None:
        """
        Parses the targets from a string.

        Args:
            targets_str (str): The text that contains the targets separated by a comma.

        """
        self._add_targets(targets_str.split(','))

    def parse_exclusions_file(self, exclusions_filepath: str) -> None:
        """Parses targets in the exclusions file and removes them from the targets list."""
        with open(exclusions_filepath, 'r', encoding='utf-8') as f:
            self._remove_targets(f)

    def parse_exclusions_str(self, exclusion_str: str) -> None:
        """Parses comma-separated exclusions and removes them from the targets list."""
        self._remove_targets(exclusion_str.split(','))

    def _classify(self, value: str) -> str:
        """Return the name of the list that `value` belongs to."""
        if self._validate_ipv4(value):
            return 'ipv4s'
        if self._validate_ipv4_with_port(value):
            return 'ipv4s_with_port'
        if self._validate_ipv6(value):
            return 'ipv6s'
        if self._validate_ipv6_with_port(value):
            return 'ipv6s_with_port'
        if self._validate_fqdn(value):
            return 'fqdns'
        if self._validate_fqdn_with_port(value):
            return 'fqdns_with_port'
        if self._validate_cidr_ipv4(value):
            return 'cidrs_v4'
        if self._validate_cidr_ipv6(value):
            return 'cidrs_v6'
        if self._validate_url(value):
            return 'urls'
        return 'invalids'

    def _add_targets(self, values: typing.Iterable[str]) -> None:
        for raw in values:
            value = raw.strip()
            if value:
                getattr(self, self._classify(value)).append(value)

        self._remove_duplicates()
        self._sort_ascending()

    def _remove_targets(self, values: typing.Iterable[str]) -> None:
        for raw in values:
            value = raw.strip()
            if value:
                self._remove_from_list(getattr(self, self._classify(value)), value)

    def total_count(self) -> int:
        """Number of targets that can be analyzed."""
        return len(self.ipv4s) + len(self.fqdns) + len(self.cidrs_v4) + len(self.urls)

    def unsupported(self) -> list[str]:
        """Valid targets that are parsed but not analyzed yet (IPv6, CIDRv6 and targets with a port)."""
        return self.ipv4s_with_port + self.ipv6s + self.ipv6s_with_port + self.fqdns_with_port + self.cidrs_v6

    def print_targets(self) -> None:
        """Prints the parsed targets in a beautifull format."""
        console = verbose.OUT

        if len(self.ipv4s) > 0:
            console.print(rich.panel.Panel.fit('IP Addresses (v4)'))
            for i in self.ipv4s:
                console.print(f' - {i}', highlight=False)

        if len(self.ipv4s_with_port) > 0:
            console.print(rich.panel.Panel.fit('IP Addresses with Port (v4)'))
            for i in self.ipv4s_with_port:
                console.print(f' - {i}', highlight=False)

        if len(self.ipv6s) > 0:
            console.print(rich.panel.Panel.fit('IP Addresses (v6)'))
            for i in self.ipv6s:
                console.print(f' - {i}', highlight=False)

        if len(self.ipv6s_with_port) > 0:
            console.print(rich.panel.Panel.fit('IP Addresses with Port (v6)'))
            for i in self.ipv6s_with_port:
                console.print(f' - {i}', highlight=False)

        if len(self.fqdns) > 0:
            console.print(rich.panel.Panel.fit('FQDNs'))
            for f in self.fqdns:
                console.print(f' - {f}', highlight=False)

        if len(self.fqdns_with_port) > 0:
            console.print(rich.panel.Panel.fit('FQDNs with Port'))
            for f in self.fqdns_with_port:
                console.print(f' - {f}', highlight=False)

        if len(self.cidrs_v4) > 0:
            console.print(rich.panel.Panel.fit('CIDRs (v4)'))
            for c in self.cidrs_v4:
                console.print(f' - {c}', highlight=False)

        if len(self.cidrs_v6) > 0:
            console.print(rich.panel.Panel.fit('CIDRs (v6)'))
            for c in self.cidrs_v6:
                console.print(f' - {c}', highlight=False)

        if len(self.urls) > 0:
            console.print(rich.panel.Panel.fit('URLs'))
            for u in self.urls:
                console.print(f' - {u}', highlight=False)

        if len(self.invalids) > 0:
            console.print(rich.panel.Panel.fit('Invalids'))
            for i in self.invalids:
                console.print(f' - {i}', highlight=False)

    def _remove_from_list(self, target_list: list[str], item: str) -> None:
        """Helper function to remove an item from a list if it exists."""
        if item in target_list:
            target_list.remove(item)

    def _remove_duplicates(self) -> None:
        """Remove all duplicate entries of the targets lists."""
        self.ipv4s = list(set(self.ipv4s))
        self.ipv4s_with_port = list(set(self.ipv4s_with_port))
        self.ipv6s = list(set(self.ipv6s))
        self.ipv6s_with_port = list(set(self.ipv6s_with_port))
        self.fqdns = list(set(self.fqdns))
        self.fqdns_with_port = list(set(self.fqdns_with_port))
        self.cidrs_v4 = list(set(self.cidrs_v4))
        self.cidrs_v6 = list(set(self.cidrs_v6))
        self.urls = list(set(self.urls))
        self.invalids = list(set(self.invalids))

    def _sort_ascending(self) -> None:
        """Sort the targets in ascending order."""
        self.ipv4s.sort(key=ipaddress.IPv4Address)
        self.ipv4s_with_port.sort()
        self.ipv6s.sort(key=ipaddress.IPv6Address)
        self.ipv6s_with_port.sort()
        self.fqdns.sort()
        self.fqdns_with_port.sort()
        self.cidrs_v4.sort(key=ipaddress.IPv4Network)
        self.cidrs_v6.sort(key=ipaddress.IPv6Network)
        self.urls.sort()
        self.invalids.sort()

    def _validate_ipv4(self, value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except Exception:
            return False

    def _validate_ipv4_with_port(self, value: str) -> bool:
        parts = value.split(':')
        if len(parts) != 2:
            return False

        ipv4, port = parts

        try:
            ipaddress.IPv4Address(ipv4)
            return 1 <= int(port) <= 65535
        except Exception:
            return False

    def _validate_ipv6(self, value: str) -> bool:
        try:
            ipaddress.IPv6Address(value)
            return True
        except Exception:
            return False

    def _validate_ipv6_with_port(self, value: str) -> bool:
        if not (value.startswith('[') and ']:' in value):
            return False

        ipv6, port = value[1:].split(']:', 1)

        try:
            ipaddress.IPv6Address(ipv6)
            return 1 <= int(port) <= 65535
        except Exception:
            return False

    def _validate_cidr_ipv4(self, value: str) -> bool:
        try:
            ipaddress.IPv4Network(value, strict=True)
            return True
        except Exception:
            return False

    def _validate_cidr_ipv6(self, value: str) -> bool:
        try:
            ipaddress.IPv6Network(value, strict=True)
            return True
        except Exception:
            return False

    def _validate_fqdn(self, value: str) -> bool:
        try:
            return fqdn.FQDN(value).is_valid
        except ValueError:
            return False

    def _validate_fqdn_with_port(self, value: str) -> bool:
        if ':' not in value:
            return False

        host, port = value.rsplit(':', 1)

        if not host or not self._validate_fqdn(host):
            return False

        try:
            return 1 <= int(port) <= 65535
        except ValueError:
            return False

    def _validate_url(self, value: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(value)
            parsed.port  # Raises `ValueError` if the port is out of range or not a number.
        except ValueError:
            return False
        return parsed.scheme in ('http', 'https', 'ftp') and bool(parsed.hostname)
