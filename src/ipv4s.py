import ipwhois
import rich.box
import rich.json
import rich.progress
import rich.table

import os
import ipaddress
import subprocess

import models
import verbose


def analyze(ipv4s: list[str]) -> list[models.IPV4]:
    final: list[models.IPV4] = []

    with rich.progress.Progress(rich.progress.SpinnerColumn(), rich.progress.TaskProgressColumn(), transient=True) as p:
        task = p.add_task("", total=len(ipv4s) + 1)

        for ipv4 in ipv4s:
            ipv4_obj = models.IPV4()
            ipv4_obj.ipv4 = ipv4

            ########
            # Math #
            ########
            ip = ipaddress.IPv4Address(ipv4)

            ##############
            # Visibility #
            ##############
            ipv4_obj.visibility = "Private" if ip.is_private else "Public"
            ipv4_is_public = ipv4_obj.visibility == "Public"

            ########
            # RDAP #
            ########
            if ipv4_is_public:
                ip = ipv4.split("/")[0]
                whois = ipwhois.IPWhois(ip)
                rdap = whois.lookup_rdap(depth=1)
            ipv4_obj.network = rdap.get("network").get("name").replace(",", "") if ipv4_is_public else "N/A"
            ipv4_obj.asn_country_code = rdap.get("asn_country_code") if ipv4_is_public else "N/A"
            ipv4_obj.asn_description = rdap.get("asn_description").replace(",", "") if ipv4_is_public else "N/A"

            ########
            # Ping #
            ########
            param = "-n" if os.sys.platform.lower() == "win32" else "-c"
            command = ["ping", param, "1", "-i 0.2", ipv4]
            ipv4_obj.pingable = subprocess.call(command, stdout=subprocess.DEVNULL) == 0

            final.append(ipv4_obj)

            p.advance(task, advance=1)

    return final


def print_as_table(ipv4s: list[models.IPV4], highlight: bool) -> None:
    c = verbose.console
    t = rich.table.Table(box=rich.box.ASCII)

    t.add_column("IP Address (v4)")
    t.add_column("Visibility")
    t.add_column("ASN Country")
    t.add_column("ASN Description")
    t.add_column("Network")
    t.add_column("Pingable")

    for ipv4 in ipv4s:
        t.add_row(
            ipv4.ipv4,
            ipv4.visibility,
            ipv4.asn_country_code,
            ipv4.asn_description,
            ipv4.network,
            "yes" if ipv4.pingable else "no",
        )

    c.print(t, highlight=highlight)


def print_as_json(ipv4s: list[models.IPV4], highlight: bool) -> None:
    c = verbose.console

    for ipv4 in ipv4s:
        c.print(rich.json.JSON(ipv4.model_dump_json(), indent=None, highlight=highlight))


def print_as_normal(ipv4s: list[models.IPV4], highlight: bool) -> None:
    c = verbose.console

    for ipv4 in ipv4s:
        if highlight:
            c.print(
                f"[white]{ipv4.type}[/white],[green]{ipv4.ipv4}[/green],[yellow]{ipv4.visibility}[/yellow],[red]{ipv4.asn_country_code}[/red],[red]{ipv4.asn_description}[/red],[red]{ipv4.network}[/red][blue],{"pingable" if ipv4.pingable else "not pingable"}[/blue]",
                highlight=False,
            )
        else:
            c.print(
                f"{ipv4.type},{ipv4.ipv4},{ipv4.visibility},{ipv4.asn_country_code},{ipv4.asn_description},{ipv4.network},{"pingable" if ipv4.pingable else "not pingable"}",
                highlight=highlight,
            )


def get_results(ipv4s: list[models.IPV4], json: bool) -> None:
    results: list[str] = []

    for ipv4 in ipv4s:
        if not json:
            results.append(
                f"{ipv4.type},{ipv4.ipv4},{ipv4.visibility},{ipv4.asn_country_code},{ipv4.asn_description},{ipv4.network},{"pingable" if ipv4.pingable else "not pingable"}"
            )
        else:
            results.append(ipv4.model_dump_json())

    return results
