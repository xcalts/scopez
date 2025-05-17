import fqdn
import pydantic

import ipaddress
import sys
import urllib.parse


class Targeter(pydantic.BaseModel):
    """Parses the `targets` stores them in different kind of formats."""

    ipv4: list[str] = []
    ipv4_with_port: list[str] = []
    ipv6: list[str] = []
    ipv6_with_port: list[str] = []
    fqdn: list[str] = []
    fqnd_with_port: list[str] = []
    cidr_ipv4: list[str] = []
    cidr_ipv6: list[str] = []
    url: list[str] = []
    invalid: list[str] = []

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
                    self.ipv4.append(val)
                elif self._validate_ipv4_with_port(val):
                    self.ipv4_with_port.append(val)
                elif self._validate_ipv6(val):
                    self.ipv6.append(val)
                elif self._validate_ipv6_with_port(val):
                    self.ipv6_with_port.append(val)
                elif self._validate_fqdn(val):
                    self.fqdn.append(val)
                elif self.validate_fqdn_with_port(val):
                    self.fqnd_with_port.append(val)
                elif self._validate_cidr_ipv4(val):
                    self.cidr_ipv4.append(val)
                elif self._validate_url(val):
                    self.url.append(val)
                else:
                    self.invalid.append(val)

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
                self.ipv4.append(val)
            elif self._validate_ipv4_with_port(val):
                self.ipv4_with_port.append(val)
            elif self._validate_ipv6(val):
                self.ipv6.append(val)
            elif self._validate_ipv6_with_port(val):
                self.ipv6_with_port.append(val)
            elif self._validate_fqdn(val):
                self.fqdn.append(val)
            elif self.validate_fqdn_with_port(val):
                self.fqnd_with_port.append(val)
            elif self._validate_cidr_ipv4(val):
                self.cidr_ipv4.append(val)
            elif self._validate_url(val):
                self.url.append(val)
            else:
                self.invalid.append(val)

        self._remove_duplicates()
        self._sort_ascending()

    def parse_exclusions_file(self, exclusions_filepath: str) -> None:
        """Parses targets in the exclusions file and removes them from the targets list."""
        # Extracting the exclusions and removing them from the target lists
        with open(exclusions_filepath) as file:
            for val in file:
                val = val.strip()
                if self._validate_ipv4(val):
                    self._remove_from_list(self.ipv4, val)
                elif self._validate_ipv4_with_port(val):
                    self._remove_from_list(self.ipv4_with_port, val)
                elif self._validate_ipv6(val):
                    self._remove_from_list(self.ipv6, val)
                elif self._validate_ipv6_with_port(val):
                    self._remove_from_list(self.ipv6_with_port, val)
                elif self._validate_fqdn(val):
                    self._remove_from_list(self.fqdn, val)
                elif self.validate_fqdn_with_port(val):
                    self._remove_from_list(self.fqnd_with_port, val)
                elif self._validate_cidr_ipv4(val):
                    self._remove_from_list(self.cidr_ipv4, val)
                elif self._validate_url(val):
                    self._remove_from_list(self.url, val)
                else:
                    self._remove_from_list(self.invalid, val)

    def parse_exclusions_str(self, exclusion_str: str) -> None:
        for val in exclusion_str.split(","):
            val = val.strip()
            if self._validate_ipv4(val):
                self._remove_from_list(self.ipv4, val)
            elif self._validate_ipv4_with_port(val):
                self._remove_from_list(self.ipv4_with_port, val)
            elif self._validate_ipv6(val):
                self._remove_from_list(self.ipv6, val)
            elif self._validate_ipv6_with_port(val):
                self._remove_from_list(self.ipv6_with_port, val)
            elif self._validate_fqdn(val):
                self._remove_from_list(self.fqdn, val)
            elif self.validate_fqdn_with_port(val):
                self._remove_from_list(self.fqnd_with_port, val)
            elif self._validate_cidr_ipv4(val):
                self._remove_from_list(self.cidr_ipv4, val)
            elif self._validate_url(val):
                self._remove_from_list(self.url, val)
            else:
                self._remove_from_list(self.invalid, val)

    def _remove_from_list(self, target_list: list[str], item: str) -> None:
        """Helper function to remove an item from a list if it exists."""
        if item in target_list:
            target_list.remove(item)

    def _remove_duplicates(self) -> None:
        """Remove all duplicate entries of the targets lists."""
        self.ipv4 = list(set(self.ipv4))
        self.ipv4_with_port = list(set(self.ipv4_with_port))
        self.ipv6 = list(set(self.ipv6))
        self.ipv6_with_port = list(set(self.ipv6_with_port))
        self.fqdn = list(set(self.fqdn))
        self.fqnd_with_port = list(set(self.fqnd_with_port))
        self.cidr_ipv4 = list(set(self.cidr_ipv4))
        self.url = list(set(self.url))
        self.invalid = list(set(self.invalid))

    def _sort_ascending(self) -> None:
        """Sort the targets in ascending order."""
        self.ipv4.sort()
        self.ipv4_with_port.sort()
        self.ipv6.sort()
        self.ipv6_with_port.sort()
        self.fqdn.sort()
        self.fqnd_with_port.sort()
        self.cidr_ipv4.sort()
        self.url.sort()
        self.invalid.sort()

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
