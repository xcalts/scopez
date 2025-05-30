import fqdn
import pydantic
import rich.panel

import ipaddress
import sys
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
        file = sys.stdin if targets_filepath == "-" else open(targets_filepath)

        with file as f:
            for line in f:
                val = line.strip()
                if self._validate_ipv4(val):
                    self.ipv4s.append(val)
                elif self._validate_ipv4_with_port(val):
                    self.ipv4s_with_port.append(val)
                elif self._validate_ipv6(val):
                    self.ipv6s.append(val)
                elif self._validate_ipv6_with_port(val):
                    self.ipv6s_with_port.append(val)
                elif self._validate_fqdn(val):
                    self.fqdns.append(val)
                elif self.validate_fqdn_with_port(val):
                    self.fqdns_with_port.append(val)
                elif self._validate_cidr_ipv4(val):
                    self.cidrs_v4.append(val)
                elif self._validate_url(val):
                    self.urls.append(val)
                else:
                    self.invalids.append(val)

        self._remove_duplicates()
        self._sort_ascending()

    def parse_targets_str(self, targets_str: str) -> None:
        """
        Parses the targets from a string.

        Args:
            targets_str (str): The text that contains the targets separted by a newline.

        """
        for val in targets_str.split(","):
            if self._validate_ipv4(val):
                self.ipv4s.append(val)
            elif self._validate_ipv4_with_port(val):
                self.ipv4s_with_port.append(val)
            elif self._validate_ipv6(val):
                self.ipv6s.append(val)
            elif self._validate_ipv6_with_port(val):
                self.ipv6s_with_port.append(val)
            elif self._validate_fqdn(val):
                self.fqdns.append(val)
            elif self.validate_fqdn_with_port(val):
                self.fqdns_with_port.append(val)
            elif self._validate_cidr_ipv4(val):
                self.cidrs_v4.append(val)
            elif self._validate_url(val):
                self.urls.append(val)
            else:
                self.invalids.append(val)

        self._remove_duplicates()
        self._sort_ascending()

    def parse_exclusions_file(self, exclusions_filepath: str) -> None:
        """Parses targets in the exclusions file and removes them from the targets list."""
        # Extracting the exclusions and removing them from the target lists
        with open(exclusions_filepath) as file:
            for val in file:
                val = val.strip()
                if self._validate_ipv4(val):
                    self._remove_from_list(self.ipv4s, val)
                elif self._validate_ipv4_with_port(val):
                    self._remove_from_list(self.ipv4s_with_port, val)
                elif self._validate_ipv6(val):
                    self._remove_from_list(self.ipv6s, val)
                elif self._validate_ipv6_with_port(val):
                    self._remove_from_list(self.ipv6s_with_port, val)
                elif self._validate_fqdn(val):
                    self._remove_from_list(self.fqdns, val)
                elif self.validate_fqdn_with_port(val):
                    self._remove_from_list(self.fqdns_with_port, val)
                elif self._validate_cidr_ipv4(val):
                    self._remove_from_list(self.cidrs_v4, val)
                elif self._validate_url(val):
                    self._remove_from_list(self.urls, val)
                else:
                    self._remove_from_list(self.invalids, val)

    def parse_exclusions_str(self, exclusion_str: str) -> None:
        for val in exclusion_str.split(","):
            val = val.strip()
            if self._validate_ipv4(val):
                self._remove_from_list(self.ipv4s, val)
            elif self._validate_ipv4_with_port(val):
                self._remove_from_list(self.ipv4s_with_port, val)
            elif self._validate_ipv6(val):
                self._remove_from_list(self.ipv6s, val)
            elif self._validate_ipv6_with_port(val):
                self._remove_from_list(self.ipv6s_with_port, val)
            elif self._validate_fqdn(val):
                self._remove_from_list(self.fqdns, val)
            elif self.validate_fqdn_with_port(val):
                self._remove_from_list(self.fqdns_with_port, val)
            elif self._validate_cidr_ipv4(val):
                self._remove_from_list(self.cidrs_v4, val)
            elif self._validate_url(val):
                self._remove_from_list(self.urls, val)
            else:
                self._remove_from_list(self.invalids, val)

    def total_count(self) -> int:
        return (
            len(self.ipv4s)
            + len(self.ipv4s_with_port)
            + len(self.ipv6s)
            + len(self.ipv6s_with_port)
            + len(self.fqdns)
            + len(self.fqdns_with_port)
            + len(self.cidrs_v4)
            + len(self.cidrs_v6)
            + len(self.urls)
        )

    def print_targets(self) -> None:
        """Prints the parsed targets in a beautifull format."""
        console = verbose.CONSOLE

        if len(self.ipv4s) > 0:
            console.print(rich.panel.Panel.fit("IP Addresses (v4)"))
            for i in self.ipv4s:
                console.print(f" - {i}", highlight=False)

        if len(self.ipv4s_with_port) > 0:
            console.print(rich.panel.Panel.fit("IP Addresses with Port (v4)"))
            for i in self.ipv4s_with_port:
                console.print(f" - {i}", highlight=False)

        if len(self.ipv6s) > 0:
            console.print(rich.panel.Panel.fit("IP Addresses (v6)"))
            for i in self.ipv6s:
                console.print(f" - {i}", highlight=False)

        if len(self.ipv6s_with_port) > 0:
            console.print(rich.panel.Panel.fit("IP Addresses with Port (v6)"))
            for i in self.ipv6s_with_port:
                console.print(f" - {i}", highlight=False)

        if len(self.fqdns) > 0:
            console.print(rich.panel.Panel.fit("FQDNs"))
            for f in self.fqdns:
                console.print(f" - {f}", highlight=False)

        if len(self.fqdns_with_port) > 0:
            console.print(rich.panel.Panel.fit("FQDNs with Port"))
            for f in self.fqdns_with_port:
                console.print(f" - {f}", highlight=False)

        if len(self.cidrs_v4) > 0:
            console.print(rich.panel.Panel.fit("CIDRs (v4)"))
            for c in self.cidrs_v4:
                console.print(f" - {c}", highlight=False)

        if len(self.cidrs_v6) > 0:
            console.print(rich.panel.Panel.fit("CIDRs (v6)"))
            for c in self.cidrs_v6:
                console.print(f" - {c}", highlight=False)

        if len(self.urls) > 0:
            console.print(rich.panel.Panel.fit("URLs"))
            for u in self.urls:
                console.print(f" - {u}", highlight=False)

        if len(self.invalids) > 0:
            console.print(rich.panel.Panel.fit("Invalids"))
            for i in self.invalids:
                console.print(f" - {i}", highlight=False)

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
        self.urls = list(set(self.urls))
        self.invalids = list(set(self.invalids))

    def _sort_ascending(self) -> None:
        """Sort the targets in ascending order."""
        self.ipv4s.sort()
        self.ipv4s_with_port.sort()
        self.ipv6s.sort()
        self.ipv6s_with_port.sort()
        self.fqdns.sort()
        self.fqdns_with_port.sort()
        self.cidrs_v4.sort()
        self.urls.sort()
        self.invalids.sort()

    def _validate_ipv4(self, value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except Exception:
            return False

    def _validate_ipv4_with_port(self, value: str) -> bool:
        parts = value.split(":")
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
        if not (value.startswith("[") and "]:" in value):
            return False

        ipv6, port = value[1:].split("]:", 1)

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
        return fqdn.FQDN(value).is_valid

    def validate_fqdn_with_port(self, value: str) -> bool:
        if ":" not in value:
            return False

        host, port = value.rsplit(":", 1)

        if not host or not self._validate_fqdn(host):
            return False

        return 1 <= int(port) <= 65535

    def _validate_url(self, value: str) -> bool:
        parsed = urllib.parse.urlparse(value)
        return parsed.scheme in ("http", "https", "ftp") and bool(parsed.netloc)
