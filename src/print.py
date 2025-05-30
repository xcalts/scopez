import rich.table
import rich.json

import models
import verbose


class Printer:
    """Prints the target's analysis' results in various formats."""

    #######
    # ALL #
    #######
    @staticmethod
    def print_as_json(targets: list[any]) -> None:
        for t in targets:
            verbose.normal(rich.json.JSON(t.model_dump_json(), indent=None))

    #########
    # CIDRs #
    #########
    @staticmethod
    def print_cidrs_as_table(cidrs: list[models.CIDR]) -> None:
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

        verbose.normal(t)

    @staticmethod
    def print_cidrs_as_raw(cidrs: list[models.CIDR]) -> None:
        for cidr in cidrs:
            verbose.normal(
                f"[white]{cidr.type}[/white],[green]{cidr.cidr}[/green],[yellow]{cidr.number_of_hosts}[/yellow],[yellow]{cidr.visibility}[/yellow],[red]{cidr.asn_country_code}[/red],[red]{cidr.asn_description}[/red],[red]{cidr.network}[/red]",
            )

    #######
    # IPs #
    #######
    @staticmethod
    def print_ipv4s_as_table(ipv4s: list[models.IPV4]) -> None:
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

        verbose.normal(t)

    def print_ipv4s_as_raw(ipv4s: list[models.IPV4]) -> None:
        for ipv4 in ipv4s:
            verbose.normal(
                f"[white]{ipv4.type}[/white],[green]{ipv4.ipv4}[/green],[yellow]{ipv4.visibility}[/yellow],[red]{ipv4.asn_country_code}[/red],[red]{ipv4.asn_description}[/red],[red]{ipv4.network}[/red][blue],{"pingable" if ipv4.pingable else "not pingable"}[/blue]"
            )

    #########
    # FQDNs #
    #########
    @staticmethod
    def print_fqdns_as_table(fqdns: list[models.FQDN]) -> None:
        t = rich.table.Table(box=rich.box.ASCII)

        t.add_column("FQDN")
        t.add_column("DNS Chain")
        t.add_column("ASN Country")
        t.add_column("ASN Description")
        t.add_column("Network")
        t.add_column("Pingable")

        for fqdn in fqdns:
            t.add_row(
                fqdn.fqdn,
                fqdn.dns_chain,
                fqdn.asn_country_code,
                fqdn.asn_description,
                fqdn.network,
                "yes" if fqdn.pingable else "no",
            )

        verbose.normal(t)

    @staticmethod
    def print_fqdns_as_raw(fqdns: list[models.FQDN]) -> None:
        for fqdn in fqdns:
            verbose.normal(
                f"[white]{fqdn.type}[/white],[green]{fqdn.fqdn}[/green],[yellow]{fqdn.dns_chain}[/yellow],[red]{fqdn.asn_country_code}[/red],[red]{fqdn.asn_description}[/red],[red]{fqdn.network}[/red],[blue]{"pingable" if fqdn.pingable else "not pingable"}[/blue]",
            )

    ########
    # URLs #
    ########
    @staticmethod
    def print_urls_as_table(urls: list[models.URL]) -> None:
        t = rich.table.Table(box=rich.box.ASCII)

        t.add_column("URL")
        t.add_column("DNS Chain")
        t.add_column("ASN Country")
        t.add_column("ASN Description")
        t.add_column("Network")
        t.add_column("Pingable")
        t.add_column("Reachable")

        for url in urls:
            t.add_row(
                url.fqdn,
                url.dns_chain,
                url.asn_country_code,
                url.asn_description,
                url.network,
                "yes" if url.pingable else "no",
                "yes" if url.reachable else "no",
            )

        verbose.normal(t)

    @staticmethod
    def print_urls_as_raw(urls: list[models.URL]) -> None:
        for url in urls:
            verbose.normal(
                f"[white]{url.type}[/white],[green]{url.url}[/green],[yellow]{url.dns_chain}[/yellow],[red]{url.asn_country_code}[/red],[red]{url.asn_description}[/red],[red]{url.network}[/red],[blue]{"pingable" if url.pingable else "not pingable"}[/blue],[blue]{"reachable" if url.reachable else "not reachable"}[/blue]",
            )
