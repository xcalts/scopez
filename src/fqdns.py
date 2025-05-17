import dns.resolver
import ipwhois
import rich.box
import rich.json
import rich.progress
import rich.table

import os

import models
import verbose


DNS_SERVERS = [
    # Google
    "8.8.8.8",
    # Google
    "8.8.4.4",
    # Control D
    "76.76.2.0",
    # Control D
    "76.76.10.0",
    # Quad9
    "9.9.9.9",
    # Quad9
    "149.112.112.112",
    # OpenDNS Home
    "208.67.222.222",
    # OpenDNS Home
    "208.67.220.220",
    # Cloudflare
    "1.1.1.1",
    # Cloudflare
    "1.0.0.1",
    # AdGuard DNS
    "94.140.14.14",
    # AdGuard DNS
    "94.140.15.15",
    # CleanBrowsing
    "185.228.168.9",
    # CleanBrowsing
    "185.228.169.9",
]


def analyze(fqdns: list[str]) -> list[models.FQDN]:
    final: list[models.FQDN] = []

    with rich.progress.Progress(rich.progress.SpinnerColumn(), rich.progress.TaskProgressColumn(), transient=True) as p:
        task = p.add_task("", total=len(fqdns))

        dns_index = 1

        for fqdn in fqdns:
            _cname: str = ""
            _ips: list[str] = []

            ######################################################################################
            # DNS                                                                                #
            # ---                                                                                #
            # Note: We need to use different DNS every time otherwise we trigger a DOS response. #
            # 1. Check if there are CNAME records for hostname.                                  #
            #    - If there CNAME records, then check for A records for the found CNAME          #
            #    - else check for A records for the hostname.                                    #
            ######################################################################################
            try:
                cname_records = dns.resolver.resolve_at(DNS_SERVERS[dns_index], fqdn, "CNAME")
                dns_index = dns_index + 1 if dns_index < len(DNS_SERVERS) else 1
                for rdap in cname_records:
                    _cname = str(rdap.target).rstrip(".")  # Remove the trailing dot.
            except dns.resolver.NoNameservers:
                fqdn_obj = models.FQDN(
                    fqdn=fqdn,
                    dns_chain=f"{fqdn} > NotFound",
                    asn_country_code="N/A",
                    asn_description="N/A",
                    network="N/A",
                    pingable=False,
                )
                final.append(fqdn_obj)
                p.advance(task, advance=1)
                continue
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                fqdn_obj = models.FQDN(
                    fqdn=fqdn,
                    dns_chain=f"{fqdn} > NotExist",
                    asn_country_code="N/A",
                    asn_description="N/A",
                    network="N/A",
                    pingable=False,
                )
                final.append(fqdn_obj)
                p.advance(task, advance=1)
                continue

            if _cname != "":
                try:
                    a_records = dns.resolver.resolve_at(DNS_SERVERS[dns_index], _cname, "A")
                    dns_index = dns_index + 1 if dns_index < len(DNS_SERVERS) else 1

                    for rdap in a_records:
                        _ips.append(str(rdap.address))

                    for ip in _ips:
                        ########
                        # RDAP #
                        ########
                        whois = ipwhois.IPWhois(ip)
                        rdap = whois.lookup_rdap(depth=1)
                        fqdn_obj = models.FQDN(
                            fqdn=fqdn,
                            dns_chain=f"{fqdn} > {_cname} > {ip}",
                            asn_country_code=rdap.get("asn_country_code"),
                            asn_description=rdap.get("asn_description").replace(",", ""),
                            network=rdap.get("network").get("name").replace(",", ""),
                        )

                        ########
                        # Ping #
                        ########
                        param = "-n" if os.sys.platform.lower() == "win32" else "-c"
                        response = os.system(f"ping {param} 1 -w2 {ip} > /dev/null 2>&1")
                        fqdn_obj.pingable = response == 0

                        final.append(fqdn_obj)
                        p.advance(task, advance=1)

                    continue

                except dns.resolver.NoAnswer:
                    pass

                except dns.resolver.NXDOMAIN:
                    fqdn_obj = models.FQDN(
                        fqdn=fqdn,
                        dns_chain=f"{fqdn} > {_cname} > NotFound",
                        asn_country_code="N/A",
                        asn_description="N/A",
                        network="N/A",
                        pingable=False,
                    )
                    final.append(fqdn_obj)
                    p.advance(task, advance=1)
                    continue
            else:
                try:
                    a_records = dns.resolver.resolve_at(DNS_SERVERS[dns_index], fqdn, "A")
                    dns_index = dns_index + 1 if dns_index < len(DNS_SERVERS) else 1

                    for rdap in a_records:
                        _ips.append(str(rdap.address))

                    for ip in _ips:
                        ########
                        # RDAP #
                        ########
                        whois = ipwhois.IPWhois(ip)
                        rdap = whois.lookup_rdap(depth=1)
                        fqdn_obj = models.FQDN(
                            fqdn=fqdn,
                            dns_chain=f"{fqdn} > {ip}",
                            asn_country_code=rdap.get("asn_country_code"),
                            asn_description=rdap.get("asn_description").replace(",", ""),
                            network=rdap.get("network").get("name").replace(",", ""),
                            pingable=False,
                        )

                        ########
                        # Ping #
                        ########
                        param = "-n" if os.sys.platform.lower() == "win32" else "-c"
                        response = os.system(f"ping {param} 1 -w2 {ip} > /dev/null 2>&1")
                        fqdn_obj.pingable = response == 0

                        final.append(fqdn_obj)
                        p.advance(task, advance=1)

                    continue

                except dns.resolver.NoAnswer:
                    pass

                except dns.resolver.NXDOMAIN:
                    fqdn_obj = models.FQDN(
                        fqdn=fqdn,
                        dns_chain=f"{fqdn} > NotFound",
                        asn_country_code="N/A",
                        asn_description="N/A",
                        network="N/A",
                        pingable=False,
                    )
                    final.append(fqdn_obj)
                    p.advance(task, advance=1)
                    continue

    return final


def print_as_table(fqdns: list[models.FQDN], highlight: bool) -> None:
    c = verbose.console
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

    c.print(t, highlight=highlight)


def print_as_json(fqdns: list[models.FQDN], highlight: bool) -> None:
    c = verbose.console

    for fqdn in fqdns:
        c.print(rich.json.JSON(fqdn.model_dump_json(), indent=None, highlight=highlight))


def print_as_normal(fqdns: list[models.FQDN], highlight: bool) -> None:
    c = verbose.console

    for fqdn in fqdns:
        if highlight:
            c.print(
                f"[green]{fqdn.fqdn}[/green],[yellow]{fqdn.dns_chain}[/yellow],[red]{fqdn.asn_country_code}[/red],[red]{fqdn.asn_description}[/red],[red]{fqdn.network}[/red],[blue]{"pingable" if fqdn.pingable else "not pingable"}[/blue]",
                highlight=False,
            )
        else:
            c.print(
                f"{fqdn.fqdn},{fqdn.dns_chain},{fqdn.asn_country_code},{fqdn.asn_description},{fqdn.network},{"pingable" if fqdn.pingable else "not pingable"}",
                highlight=highlight,
            )
