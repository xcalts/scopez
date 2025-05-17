import rich.progress
import rich.table
import rich.json
import rich.box
import pydantic
import ipwhois

import ipaddress
import time

import verbose


class CIDR(pydantic.BaseModel):
    cidr: str = ""
    number_of_hosts: int = 0
    visibility: str = ""
    asn_country_code: str = ""
    asn_description: str = ""
    network: str = ""


def analyze(cidrs: list[str]) -> list[CIDR]:
    c = verbose.console

    final: list[CIDR] = []

    with rich.progress.Progress(rich.progress.SpinnerColumn(), transient=True) as p:
        task = p.add_task("", total=len(cidrs))

        for cidr in cidrs:
            cidr_obj = CIDR()
            cidr_obj.cidr = cidr

            ########
            # Math #
            ########
            network = ipaddress.IPv4Network(cidr, strict=False)
            cidr_obj.number_of_hosts = network.num_addresses - 2

            ##############
            # Visibility #
            ##############
            cidr_obj.visibility = "Private" if network.is_private else "Public"
            cidr_is_public = cidr_obj.visibility == "Public"

            ########
            # RDAP #
            ########
            if cidr_is_public:
                ip = cidr.split("/")[0]
                whois = ipwhois.IPWhois(ip)
                rdap = whois.lookup_rdap(depth=1)
            cidr_obj.network = rdap.get("network").get("name").replace(",", "") if cidr_is_public else "N/A"
            cidr_obj.asn_country_code = rdap.get("asn_country_code") if cidr_is_public else "N/A"
            cidr_obj.asn_description = rdap.get("asn_description").replace(",", "") if cidr_is_public else "N/A"

            final.append(cidr_obj)

            p.advance(task, advance=1)

    return final


def print_as_table(cidrs: list[CIDR], highlight: bool) -> None:
    c = verbose.console
    t = rich.table.Table(box=rich.box.ASCII)

    t.add_column("CIDR")
    t.add_column("Possible # of Hosts")
    t.add_column("Visibility")
    t.add_column("ASN Country")
    t.add_column("ASN Description")
    t.add_column("Network")

    for cidr in cidrs:
        t.add_row(
            cidr.cidr,
            str(cidr.number_of_hosts),
            cidr.visibility,
            cidr.asn_country_code,
            cidr.asn_description,
            cidr.network,
        )

    c.print(t, highlight=highlight)


def print_as_json(cidrs: list[CIDR], highlight: bool) -> None:
    c = verbose.console

    for cidr in cidrs:
        c.print(rich.json.JSON(cidr.model_dump_json(), indent=None, highlight=highlight))


def print_as_normal(cidrs: list[CIDR], highlight: bool) -> None:
    c = verbose.console

    for cidr in cidrs:
        if highlight:
            c.print(
                f"[green]{cidr.cidr}[/green],[yellow]{cidr.number_of_hosts}[/yellow],[yellow]{cidr.visibility}[/yellow],[red]{cidr.asn_country_code}[/red],[red]{cidr.asn_description}[/red],[red]{cidr.network}[/red]",
                highlight=False,
            )
        else:
            c.print(
                f"{cidr.cidr},{cidr.number_of_hosts},{cidr.visibility},{cidr.asn_country_code},{cidr.asn_description},{cidr.network}",
                highlight=highlight,
            )
