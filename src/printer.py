import rich.table
import rich.json
from rich.console import Console

import models
import verbose


class Printer:
    """Prints the target's analysis' results in various formats."""

    @staticmethod
    def _output(content, output_file=None):
        """Helper method to output content to console or file."""
        if output_file:
            with open(output_file, 'a') as f:
                console = Console(file=f)
                console.print(content)
        else:
            verbose.normal(content)

    #
    # ALL
    #

    @staticmethod
    def print_as_json(targets: list[any], output_file=None) -> None:
        for t in targets:
            Printer._output(rich.json.JSON(t.model_dump_json(), indent=None), output_file)

    #
    # CIDRs
    #

    @staticmethod
    def print_cidrs_as_table(cidrs: list[models.CIDR], output_file=None) -> None:
        t = rich.table.Table(box=rich.box.ASCII)

        t.add_column('CIDR')
        t.add_column('Possible # of Hosts')
        t.add_column('Visibility')
        t.add_column('ASN Country')
        t.add_column('ASN Description')
        t.add_column('ASN Network')
        t.add_column('GeoIP Continent')
        t.add_column('GeoIP Country')

        for cidr in cidrs:
            t.add_row(
                cidr.cidr,
                str(cidr.number_of_hosts),
                cidr.visibility,
                cidr.asn_country_code,
                cidr.asn_description,
                cidr.asn_network,
                cidr.geoip_continent,
                cidr.geoip_country,
            )

        Printer._output(t, output_file)

    @staticmethod
    def print_cidrs_as_raw(cidrs: list[models.CIDR], output_file=None) -> None:
        for cidr in cidrs:
            Printer._output(
                f'[white]{cidr.type}[/white],[green]{cidr.cidr}[/green],[yellow]{cidr.number_of_hosts}[/yellow],[yellow]{cidr.visibility}[/yellow],[red]{cidr.asn_country_code}[/red],[red]{cidr.asn_description}[/red],[red]{cidr.asn_network}[/red]',
                output_file,
            )

    #
    # IPs
    #

    @staticmethod
    def print_ipv4s_as_table(ipv4s: list[models.IPV4], output_file=None) -> None:
        t = rich.table.Table(box=rich.box.ASCII)

        t.add_column('IP Address (v4)')
        t.add_column('Visibility')
        t.add_column('ASN Country')
        t.add_column('ASN Description')
        t.add_column('ASN Network')
        t.add_column('GeoIP Continent')
        t.add_column('GeoIP Country')
        t.add_column('Pingable')

        for ipv4 in ipv4s:
            t.add_row(
                ipv4.ipv4,
                ipv4.visibility,
                ipv4.asn_country_code,
                ipv4.asn_description,
                ipv4.asn_network,
                ipv4.geoip_continent,
                ipv4.geoip_country,
                'yes' if ipv4.pingable else 'no',
            )

        Printer._output(t, output_file)

    @staticmethod
    def print_ipv4s_as_raw(ipv4s: list[models.IPV4], output_file=None) -> None:
        for ipv4 in ipv4s:
            Printer._output(
                f'[white]{ipv4.type}[/white],'
                f'[green]{ipv4.ipv4}[/green],'
                f'[yellow]{ipv4.visibility}[/yellow],'
                f'[red]{ipv4.asn_country_code}[/red],'
                f'[red]{ipv4.asn_description}[/red],'
                f'[red]{ipv4.asn_network}[/red],'
                f'[blue]{"pingable" if ipv4.pingable else "not pingable"}[/blue]',
                output_file,
            )

    #
    # FQDNs
    #

    @staticmethod
    def print_fqdns_as_table(fqdns: list[models.FQDN], output_file=None) -> None:
        t = rich.table.Table(box=rich.box.ASCII)

        t.add_column('FQDN')
        t.add_column('DNS Chain')
        t.add_column('ASN Country')
        t.add_column('ASN Description')
        t.add_column('ASN Network')
        t.add_column('GeoIP Continent')
        t.add_column('GeoIP Country')
        t.add_column('Pingable')

        for fqdn in fqdns:
            if fqdn.hosts_found:
                for ip in fqdn.destination_ips:
                    t.add_row(
                        fqdn.fqdn,
                        ' > '.join(fqdn.dns_chain) + f' > {ip.ipv4}',
                        ip.asn_country_code,
                        ip.asn_description,
                        ip.asn_network,
                        ip.geoip_continent,
                        ip.geoip_country,
                        'yes' if ip.pingable else 'no',
                    )
            else:
                t.add_row(
                    fqdn.fqdn,
                    ' > '.join(fqdn.dns_chain) + ' > Not Found',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                )

        Printer._output(t, output_file)

    @staticmethod
    def print_fqdns_as_raw(fqdns: list[models.FQDN], output_file=None) -> None:
        for fqdn in fqdns:
            if fqdn.hosts_found:
                for ip in fqdn.destination_ips:
                    Printer._output(
                        f'[white]{fqdn.type}[/white],[green]{fqdn.fqdn}[/green],[yellow]{" > ".join(fqdn.dns_chain) + f" > {ip}"}[/yellow],[red]{ip.asn_country_code}[/red],[red]{ip.asn_description}[/red],[red]{ip.asn_network}[/red],[red]{ip.geoip_continent}[/red],[red]{ip.geoip_country}[/red],[blue]{"yes" if ip.pingable else "no"}[/blue]',
                        output_file,
                    )
            else:
                Printer._output(
                    f'[white]{fqdn.type}[/white],[green]{fqdn.fqdn}[/green],[yellow]{" > ".join(fqdn.dns_chain) + " > Not Found"}[/yellow],[red]N/A[/red],[red]N/A[/red],[red]N/A[/red],[red]N/A[/red],[red]N/A[/red],[blue]N/A[/blue]',
                    output_file,
                )

    #
    # URLs
    #

    @staticmethod
    def print_urls_as_table(urls: list[models.URL], output_file=None) -> None:
        t = rich.table.Table(box=rich.box.ASCII)

        t.add_column('URL')
        t.add_column('DNS Chain')
        t.add_column('ASN Country')
        t.add_column('ASN Description')
        t.add_column('ASN Network')
        t.add_column('GeoIP Continent')
        t.add_column('GeoIP Country')
        t.add_column('Pingable')
        t.add_column('Reachable')

        for url in urls:
            if url.fqdn.hosts_found:
                for ip in url.fqdn.destination_ips:
                    t.add_row(
                        url.url,
                        ' > '.join(url.fqdn.dns_chain) + f' > {ip.ipv4}',
                        ip.asn_country_code,
                        ip.asn_description,
                        ip.asn_network,
                        ip.geoip_continent,
                        ip.geoip_country,
                        'yes' if ip.pingable else 'no',
                        'yes' if url.reachable else 'no',
                    )
            else:
                t.add_row(
                    url.url,
                    ' > '.join(url.fqdn.dns_chain) + ' > Not Found',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A',
                )

        Printer._output(t, output_file)

    @staticmethod
    def print_urls_as_raw(urls: list[models.URL], output_file=None) -> None:
        for url in urls:
            if url.fqdn.hosts_found:
                for ip in url.fqdn.destination_ips:
                    Printer._output(
                        f'[white]{url.type}[/white],[green]{url.url}[/green],[yellow]{" > ".join(url.fqdn.dns_chain) + f" > {ip}"}[/yellow],[red]{ip.asn_country_code}[/red],[red]{ip.asn_description}[/red],[red]{ip.asn_network}[/red],[red]{ip.geoip_continent}[/red],[red]{ip.geoip_country}[/red],[blue]{"yes" if ip.pingable else "no"}[/blue],[blue]{"yes" if url.reachable else "no"}[/blue]',
                        output_file,
                    )
            else:
                Printer._output(
                    f'[white]{url.type}[/white],[green]{url.url}[/green],[yellow]{" > ".join(url.fqdn.dns_chain) + " > Not Found"}[/yellow],[red]N/A[/red],[red]N/A[/red],[red]N/A[/red],[red]N/A[/red],[red]N/A[/red],[blue]N/A[/blue],[blue]N/A[/blue]',
                    output_file,
                )

    #
    # Invalids
    #

    @staticmethod
    def print_invalids_as_table(invalids: list[str], output_file=None) -> None:
        t = rich.table.Table(box=rich.box.ASCII)

        t.add_column('Invalid')

        for invalid in invalids:
            t.add_row(invalid)

        Printer._output(t, output_file)

    @staticmethod
    def print_invalids_as_raw(invalids: list[str], output_file=None) -> None:
        for invalid in invalids:
            Printer._output(f'[white]invalid[/white],[red]{invalid}[/red]', output_file)
