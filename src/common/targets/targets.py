import pydantic
import rich.console
import rich.panel

import re

IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
IPV4_WITH_PORT_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$")
IPV6_REGEX = re.compile(
    r"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$"
)
IPV6_WITH_PORT_REGEX = re.compile(
    r"^\[(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9]))\]:\d{1,5}$"
)
HOST_REGEX = re.compile(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")
HOST_WITH_PORT_REGEX = re.compile(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}):\d{1,5}$")
CIDR_REGEX = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$")
URL_REGEX = re.compile(r"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$")


class Targeter(pydantic.BaseModel):
    """Parses the `targets` stores them in different kind of formats."""

    ipv4: list[str] = []
    ipv4_with_port: list[str] = []
    ipv6: list[str] = []
    ipv6_with_port: list[str] = []
    host: list[str] = []
    host_with_port: list[str] = []
    cidr: list[str] = []
    url: list[str] = []
    invalid: list[str] = []

    def list_all_targets(self) -> list[str]:
        """Returns a list that contains all the targets."""

        return (
            self.ipv4
            + self.ipv4_with_port
            + self.ipv6
            + self.host
            + self.cidr
            + self.NAMED_CIDRs
            + self.FOR_NESSUSs
            + self.url
        )

    def parse_targets_file(self, targets_filepath: str) -> None:
        """
        Parses the targets from a text file.

        Args:
            targets_filepath (str): The text file that contains the targets separted by a newline.
        """

        with open(targets_filepath, "r") as file:
            for l in file:
                l = l.strip()
                if bool(IPV4_REGEX.match(l)):
                    self.ipv4.append(l)
                elif bool(IPV4_WITH_PORT_REGEX.match(l)):
                    self.ipv4_with_port.append(l)
                elif bool(IPV6_REGEX.match(l)):
                    self.ipv6.append(l)
                elif bool(IPV6_WITH_PORT_REGEX.match(l)):
                    self.ipv6_with_port.append(l)
                elif bool(HOST_REGEX.match(l)):
                    self.host.append(l)
                elif bool(HOST_WITH_PORT_REGEX.match(l)):
                    self.host.append(l)
                elif bool(CIDR_REGEX.match(l)):
                    self.cidr.append(l)
                elif bool(URL_REGEX.match(l)):
                    self.url.append(l)
                else:
                    self.invalid.append(l)

        self._remove_duplicates()
        self._sort_ascending()

    def parse_targets_str(self, targets_str: str) -> None:
        """
        Parses the targets from a string.

        Args:
            targets_str (str): The text that contains the targets separted by a newline.
        """

        for l in targets_str.split("\n"):
            if bool(IPV4_REGEX.match(l)):
                self.ipv4.append(l)
            elif bool(IPV4_WITH_PORT_REGEX.match(l)):
                self.ipv4_with_port.append(l)
            elif bool(IPV6_REGEX.match(l)):
                self.ipv6.append(l)
            elif bool(IPV6_WITH_PORT_REGEX.match(l)):
                self.ipv6_with_port.append(l)
            elif bool(HOST_REGEX.match(l)):
                self.host.append(l)
            elif bool(HOST_WITH_PORT_REGEX.match(l)):
                self.host.append(l)
            elif bool(CIDR_REGEX.match(l)):
                self.cidr.append(l)
            elif bool(URL_REGEX.match(l)):
                self.url.append(l)
            else:
                self.invalid.append(l)

        self._remove_duplicates()
        self._sort_ascending()

    def print_targets(self, prefix="") -> None:
        """Prints the parsed targets in a beautifull format.

        Args:
            prefix (str, optional): Prefix text to input on every line of the output. Defaults to "".
        """
        console = rich.console.Console()

        if len(self.ipv4) > 0:
            console.print(rich.panel.Panel.fit("IPV4s"))
            for ipv4 in self.ipv4:
                console.print(f"{prefix}  - 💻 {ipv4}")

        if len(self.ipv4_with_port) > 0:
            console.print(rich.panel.Panel.fit("IPV4:PORT"))
            for ipv4_port in self.ipv4_with_port:
                console.print(f"{prefix}  - 💻 {ipv4_port}")

        if len(self.ipv6) > 0:
            console.print(rich.panel.Panel.fit("IPV6s"))
            for ipv6 in self.ipv6:
                console.print(f"{prefix}  - 💻 {ipv6}")

        if len(self.ipv6) > 0:
            console.print(rich.panel.Panel.fit("IPV6s:PORT"))
            for ipv6 in self.ipv6_with_port:
                console.print(f"{prefix}  - 💻 {ipv6}")

        if len(self.host) > 0:
            console.print(rich.panel.Panel.fit("Hostnames"))
            for hostname in self.host:
                console.print(f"{prefix}  - 🔖 {hostname}")

        if len(self.cidr) > 0:
            console.print(rich.panel.Panel.fit("CIDRs"))
            for named_cidr in self.cidr:
                console.print(f"{prefix}  - 🏭 {named_cidr}")

        if len(self.url) > 0:
            console.print(rich.panel.Panel.fit("URLs"))
            for url in self.url:
                console.print(f"{prefix}  - 🌎 {url}")

        if len(self.invalid) > 0:
            console.print(rich.panel.Panel.fit("Invalids"))
            for invalid in self.invalid:
                console.print(f"{prefix}  - 💔 {invalid}")

    def print_urls(self, prefix="") -> None:
        """Prints the parsed URLs in a beautifull format.

        Args:
            prefix (str, optional): Prefix text to input on every line of the output. Defaults to "".
        """
        console = rich.console.Console()

        console.print(rich.panel.Panel.fit("URLs"))
        for url in self.url:
            console.print(f"{prefix}  - 🌎 {url}")

    def convert_hostnames_to_urls(self) -> None:
        """For each and every parsed hostname, create a HTTPs URL of it."""

        for hostname in self.host:
            self.url.append(f"https://{hostname}")

        self._remove_duplicates()
        self._sort_ascending()

    def _remove_from_list(self, target_list, item) -> None:
        """Helper function to remove an item from a list if it exists."""

        if item in target_list:
            target_list.remove(item)

    def _targets_count(self) -> int:
        """Return the total of the targets."""

        return len(self.ipv4) + len(self.ipv6) + len(self.host) + len(self.cidr) + len(self.FOR_NESSUSs) + len(self.url)

    def _remove_duplicates(self) -> None:
        """Remove all duplicate entries of the targets lists."""

        self.ipv4 = list(set(self.ipv4))
        self.ipv6 = list(set(self.ipv6))
        self.host = list(set(self.host))
        self.cidr = list(set(self.cidr))
        self.url = list(set(self.url))
        self.invalid = list(set(self.invalid))

    def _sort_ascending(self) -> None:
        """Sort the targets in ascending order."""
        self.ipv4.sort()
        self.ipv4_with_port.sort()
        self.ipv6.sort()
        self.host.sort()
        self.cidr.sort()
        self.url.sort()
