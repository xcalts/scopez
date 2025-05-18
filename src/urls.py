import dns.resolver
import ipwhois
import rich.box
import rich.json
import rich.progress
import rich.table
import requests

import os
import subprocess
import urllib.parse

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


def analyze(urls: list[str]) -> list[models.URL]:
    final: list[models.URL] = []

    with rich.progress.Progress(rich.progress.SpinnerColumn(), rich.progress.TaskProgressColumn(), transient=True) as p:
        task = p.add_task("", total=len(urls) + 1)

        dns_index = 1

        for url in urls:
            parsed_url = urllib.parse.urlparse(url)

            parsed_port = parsed_url.port if parsed_url.port != None else 443 if parsed_url.scheme == "https" else 80

            url_obj = models.URL(
                url=url,
                scheme=parsed_url.scheme,
                username=parsed_url.username if parsed_url.username != None else "",
                password=parsed_url.password if parsed_url.password != None else "",
                fqdn=parsed_url.hostname,
                port=parsed_port,
                path=parsed_url.path,
            )

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
                cname_records = dns.resolver.resolve_at(DNS_SERVERS[dns_index], url_obj.fqdn, "CNAME")
                dns_index = dns_index + 1 if dns_index < len(DNS_SERVERS) else 1
                for rdap in cname_records:
                    _cname = str(rdap.target).rstrip(".")  # Remove the trailing dot.
            except dns.resolver.NoNameservers:
                url_obj.dns_chain = f"{url} > NotFound"
                url_obj.asn_country_code = "N/A"
                url_obj.asn_description = "N/A"
                url_obj.network = "N/A"
                url_obj.pingable = False
                final.append(url_obj)
                p.advance(task, advance=1)
                continue
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                url_obj.dns_chain = f"{url} > NotExist"
                url_obj.asn_country_code = "N/A"
                url_obj.asn_description = "N/A"
                url_obj.network = "N/A"
                url_obj.pingable = False
                final.append(url_obj)
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
                        url_obj.dns_chain = f"{url} > {_cname} > {ip}"
                        url_obj.asn_country_code = rdap.get("asn_country_code")
                        url_obj.asn_description = rdap.get("asn_description").replace(",", "")
                        url_obj.network = rdap.get("network").get("name").replace(",", "")

                        ########
                        # Ping #
                        ########
                        param = "-n" if os.sys.platform.lower() == "win32" else "-c"
                        command = ["ping", param, "1", "-i 0.2", url_obj.fqdn]
                        url_obj.pingable = subprocess.call(command, stdout=subprocess.DEVNULL) == 0

                        ########
                        # CURL #
                        ########
                        try:
                            response = requests.get(url_obj.url, verify=False, timeout=2)
                            response.raise_for_status()
                            url_obj.reachable = True
                        except Exception:
                            url_obj.reachable = False

                        final.append(url_obj)

                    p.advance(task, advance=1)
                    continue

                except dns.resolver.NoAnswer:
                    pass

                except dns.resolver.NXDOMAIN:
                    url_obj.dns_chain = f"{url} > {_cname} > NotFound"
                    url_obj.asn_country_code = "N/A"
                    url_obj.asn_description = "N/A"
                    url_obj.network = "N/A"
                    url_obj.pingable = False
                    final.append(url_obj)
                    p.advance(task, advance=1)
                    continue
            else:
                try:
                    a_records = dns.resolver.resolve_at(DNS_SERVERS[dns_index], url_obj.fqdn, "A")
                    dns_index = dns_index + 1 if dns_index < len(DNS_SERVERS) else 1

                    for rdap in a_records:
                        _ips.append(str(rdap.address))

                    for ip in _ips:
                        ########
                        # RDAP #
                        ########
                        whois = ipwhois.IPWhois(ip)
                        rdap = whois.lookup_rdap(depth=1)
                        url_obj.dns_chain = f"{url} > {ip}"
                        url_obj.asn_country_code = rdap.get("asn_country_code")
                        url_obj.asn_description = rdap.get("asn_description").replace(",", "")
                        url_obj.network = rdap.get("network").get("name").replace(",", "")

                        ########
                        # Ping #
                        ########
                        param = "-n" if os.sys.platform.lower() == "win32" else "-c"
                        command = ["ping", param, "1", "-i 0.2", url_obj.fqdn]
                        url_obj.pingable = subprocess.call(command, stdout=subprocess.DEVNULL) == 0

                        ########
                        # CURL #
                        ########
                        try:
                            response = requests.get(url_obj.url, verify=False, timeout=2)
                            response.raise_for_status()
                            url_obj.reachable = True
                        except Exception:
                            url_obj.reachable = False

                        final.append(url_obj)

                    p.advance(task, advance=1)
                    continue

                except dns.resolver.NoAnswer:
                    pass

                except dns.resolver.NXDOMAIN:
                    url_obj.dns_chain = f"{url} > NotFound"
                    url_obj.asn_country_code = "N/A"
                    url_obj.asn_description = "N/A"
                    url_obj.network = "N/A"
                    url_obj.pingable = False
                    final.append(url_obj)
                    p.advance(task, advance=1)
                    continue

        p.stop_task(task)

    return final


def print_as_table(urls: list[models.URL], highlight: bool) -> None:
    c = verbose.console
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

    c.print(t, highlight=highlight)


def print_as_json(urls: list[models.URL], highlight: bool) -> None:
    c = verbose.console

    for url in urls:
        c.print(rich.json.JSON(url.model_dump_json(), indent=None, highlight=highlight))


def print_as_normal(urls: list[models.URL], highlight: bool) -> None:
    c = verbose.console

    for url in urls:
        if highlight:
            c.print(
                f"[white]{url.type}[/white],[green]{url.url}[/green],[yellow]{url.dns_chain}[/yellow],[red]{url.asn_country_code}[/red],[red]{url.asn_description}[/red],[red]{url.network}[/red],[blue]{"pingable" if url.pingable else "not pingable"}[/blue],[blue]{"reachable" if url.reachable else "not reachable"}[/blue]",
                highlight=False,
            )
        else:
            c.print(
                f"{url.type},{url.fqdn},{url.dns_chain},{url.asn_country_code},{url.asn_description},{url.network},{"pingable" if url.pingable else "not pingable"},{"reachable" if url.reachable else "not reachable"}",
                highlight=highlight,
            )


def get_results(urls: list[models.URL], json: bool) -> None:
    results: list[str] = []

    for fqdn in urls:
        if not json:
            results.append(
                f"{fqdn.type},{fqdn.fqdn},{fqdn.dns_chain},{fqdn.asn_country_code},{fqdn.asn_description},{fqdn.network},{"pingable" if fqdn.pingable else "not pingable"},{"reachable" if fqdn.pingable else "not reachable"}"
            )
        else:
            results.append(fqdn.model_dump_json())

    return results
