import pydantic
import ipwhois
import ipwhois.exceptions
import dns.exception
import dns.resolver
import requests
import pandas

import bisect
import ipaddress
import socket
import subprocess
import sys
import concurrent.futures
import random
import urllib.parse
import time

import models
import verbose


RDAP_MAX_ATTEMPTS = 3
RDAP_RETRY_DELAY = 5
DNS_MAX_TIMEOUTS = 3
DNS_QUERY_DELAY = 0.2
MAX_CNAME_CHAIN = 16
DEFAULT_PORTS = {'http': 80, 'https': 443, 'ftp': 21}


class Analyzer(pydantic.BaseModel):
    """Analyzes raw targets and populates them with additional information."""

    analyzed_ipv4s: list[models.IPV4] = []
    analyzed_cidrs: list[models.CIDR] = []
    analyzed_fqdns: list[models.FQDN] = []
    analyzed_urls: list[models.URL] = []

    # GeoIP index: networks sorted by their first address, for binary search.
    _geoip_starts: list[int] = pydantic.PrivateAttr(default_factory=list)
    _geoip_ends: list[int] = pydantic.PrivateAttr(default_factory=list)
    _geoip_locations: list[tuple[str, str]] = pydantic.PrivateAttr(default_factory=list)

    def parse_geoip_data(self, geoip_csv_database_filepath: str) -> None:
        data_frame = pandas.read_csv(
            geoip_csv_database_filepath,
            usecols=['network', 'continent_name', 'country_name'],
        ).fillna('')

        entries = []
        for network, continent, country in data_frame.itertuples(index=False, name=None):
            net = ipaddress.IPv4Network(network)
            entries.append((int(net.network_address), int(net.broadcast_address), (continent, country)))
        entries.sort(key=lambda e: e[0])

        self._geoip_starts = [e[0] for e in entries]
        self._geoip_ends = [e[1] for e in entries]
        self._geoip_locations = [e[2] for e in entries]

    def analyze_ipv4s(self, ipv4s: list[str], no_threads: int) -> None:
        """Analyze the IP addresses (v4) and populate them with information.

        Args:
            ipv4s (list[str]): A list of IP addresses in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        verbose.debug('Analyze IPV4s.')
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            self.analyzed_ipv4s.extend(executor.map(self._populate_ipv4, ipv4s))

    def analyze_cidrs(self, cidrs: list[str], no_threads: int) -> None:
        """Analyze the CIDR IP addresses (v4) and populate them with information.

        Args:
            cidrs (list[str]): A list of CIDR IP addresses in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        verbose.debug('Analyze CIDRs.')
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            self.analyzed_cidrs.extend(executor.map(self._populate_cidr, cidrs))

    def analyze_fqdns(self, fqdns: list[str], no_threads: int) -> None:
        """Analyze the FQDNs and populate them with information.

        Args:
            fqdns (list[str]): A list of FQDNs in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        verbose.debug('Analyze FQDNs.')
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            self.analyzed_fqdns.extend(executor.map(self._populate_fqdn, fqdns))

    def analyze_urls(self, urls: list[str], no_threads: int) -> None:
        """Analyze the URLS and populate them with information.

        Args:
            urls (list[str]): A list of URLs in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        verbose.debug('Analyze URLs.')
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            self.analyzed_urls.extend(executor.map(self._populate_url, urls))

    #
    # Populate
    #

    def _populate_ipv4(self, ipv4: str) -> models.IPV4:
        verbose.debug(f'Analyze {ipv4}.')

        ip = ipaddress.IPv4Address(ipv4)
        ipv4_obj = models.IPV4(ipv4=ipv4, visibility='Private' if ip.is_private else 'Public')

        if ipv4_obj.visibility == 'Public':
            self._apply_rdap(ipv4_obj, self._rdap_lookup(ipv4))
            ipv4_obj.geoip_continent, ipv4_obj.geoip_country = self._geoip_lookup(int(ip), int(ip))
            ipv4_obj.pingable = self._ping(ipv4)
        else:
            self._apply_rdap(ipv4_obj, {})
            ipv4_obj.geoip_continent = 'N/A'
            ipv4_obj.geoip_country = 'N/A'
            ipv4_obj.pingable = False

        verbose.debug(f'Finished {ipv4}.')
        return ipv4_obj

    def _populate_cidr(self, cidr: str) -> models.CIDR:
        verbose.debug(f'Analyze {cidr}.')

        network = ipaddress.IPv4Network(cidr, strict=False)
        cidr_obj = models.CIDR(
            cidr=cidr,
            number_of_hosts=self._usable_hosts(network),
            visibility='Private' if network.is_private else 'Public',
        )

        if cidr_obj.visibility == 'Public':
            self._apply_rdap(cidr_obj, self._rdap_lookup(str(network.network_address)))
            cidr_obj.geoip_continent, cidr_obj.geoip_country = self._geoip_lookup(
                int(network.network_address), int(network.broadcast_address)
            )
        else:
            self._apply_rdap(cidr_obj, {})
            cidr_obj.geoip_continent = 'N/A'
            cidr_obj.geoip_country = 'N/A'

        verbose.debug(f'Finished {cidr}.')
        return cidr_obj

    def _populate_fqdn(self, fqdn: str) -> models.FQDN:
        verbose.debug(f'Analyze {fqdn}.')

        ######################################################################################
        # Notes:                                                                             #
        # - We need to use different DNS every time otherwise we trigger a DOS response.     #
        # - A FQDN can point only to a *single* CNAME (RFC 1034 & RFC 2181).                 #
        # - A FQDN can point to multiple IP addresses (Load-Balancing).                      #
        # - A FQDN cannot have a CNAME and A/AAA records at the same time.                   #
        ######################################################################################
        f = models.FQDN(fqdn=fqdn, dns_chain=[fqdn])

        # Follow the CNAME chain.
        while True:
            answer = self._resolve(f.dns_chain[-1], 'CNAME')
            if answer is None:
                break

            cname = str(answer[0].target).rstrip('.')  # Remove the trailing dot.
            if cname in f.dns_chain or len(f.dns_chain) >= MAX_CNAME_CHAIN:
                verbose.debug(f'{f.dns_chain[-1]}: CNAME loop or chain too long - stop following it')
                break

            f.dns_chain.append(cname)

        # For the last link in the DNS chain, check its A records.
        answer = self._resolve(f.dns_chain[-1], 'A')
        if answer is not None:
            f.hosts_found = True
            for record in answer:
                f.destination_ips.append(self._populate_ipv4(str(record.address)))

        verbose.debug(f'Finished {fqdn}.')
        return f

    def _populate_url(self, url: str) -> models.URL:
        verbose.debug(f'Analyze {url}.')

        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or DEFAULT_PORTS.get(parsed_url.scheme, 80)

        u = models.URL(
            url=url,
            scheme=parsed_url.scheme,
            username=parsed_url.username or '',
            password=parsed_url.password or '',
            port=port,
            path=parsed_url.path,
        )

        if self._is_ipv4(host):
            # An IP literal has no DNS chain; analyze the IP directly.
            u.fqdn = models.FQDN(
                fqdn=host, dns_chain=[host], hosts_found=True, destination_ips=[self._populate_ipv4(host)]
            )
        else:
            u.fqdn = self._populate_fqdn(host)

        u.reachable = self._is_reachable(u, host)

        verbose.debug(f'Finished {url}.')
        return u

    #
    # Helpers
    #

    @staticmethod
    def _usable_hosts(network: ipaddress.IPv4Network) -> int:
        if network.prefixlen == 32:
            return 1
        if network.prefixlen == 31:
            return 2  # Point-to-point link (RFC 3021).
        return network.num_addresses - 2

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _rdap_lookup(ip: str) -> dict:
        """Query RDAP for `ip`, retrying a few times on transient errors. Returns `{}` on failure."""
        for attempt in range(1, RDAP_MAX_ATTEMPTS + 1):
            try:
                return ipwhois.IPWhois(ip).lookup_rdap(depth=1) or {}
            except ipwhois.exceptions.IPDefinedError as e:
                # Reserved/special-purpose addresses (e.g. multicast) have no RDAP data.
                verbose.debug(f'{ip}: RDAP - {e}')
                return {}
            except Exception as e:
                verbose.debug(f'{ip}: RDAP attempt {attempt}/{RDAP_MAX_ATTEMPTS} failed - {e}')
                if attempt < RDAP_MAX_ATTEMPTS:
                    time.sleep(RDAP_RETRY_DELAY)
        return {}

    @staticmethod
    def _apply_rdap(obj: models.IPV4 | models.CIDR, rdap: dict) -> None:
        network = rdap.get('network') or {}
        obj.asn_network = str(network.get('name') or 'N/A').replace(',', '')
        obj.asn_country_code = rdap.get('asn_country_code') or 'N/A'
        obj.asn_description = str(rdap.get('asn_description') or 'N/A').replace(',', '')

    def _geoip_lookup(self, first: int, last: int) -> tuple[str, str]:
        """Return (continent, country) for the address range `first`..`last`.

        Returns 'Multiple' if the range spans more than one GeoIP network and 'N/A' if it is unknown.
        """
        i = bisect.bisect_right(self._geoip_starts, first) - 1
        if i < 0 or self._geoip_ends[i] < first:
            return 'N/A', 'N/A'
        if self._geoip_ends[i] < last:
            return 'Multiple', 'Multiple'
        continent, country = self._geoip_locations[i]
        return continent or 'N/A', country or 'N/A'

    @staticmethod
    def _ping(ip: str) -> bool:
        if sys.platform == 'win32':
            command = ['ping', '-n', '1', '-w', '2000', ip]  # -w: timeout in ms
        elif sys.platform == 'darwin':
            command = ['ping', '-c', '1', '-W', '2000', ip]  # -W: timeout in ms
        else:
            command = ['ping', '-c', '1', '-W', '2', ip]  # -W: timeout in s
        try:
            return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10) == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _resolve(name: str, rdtype: str) -> dns.resolver.Answer | None:
        """Resolve `name` using a random public DNS server. Returns `None` if there is no answer."""
        timeouts = 0
        while True:
            try:
                answer = dns.resolver.resolve_at(random.choice(DNS_SERVERS), name, rdtype, lifetime=10)
                time.sleep(DNS_QUERY_DELAY)
                return answer
            except dns.resolver.NXDOMAIN:
                verbose.debug(f'{name}: NXDOMAIN - domain does not exist')
            except dns.resolver.NoAnswer:
                verbose.debug(f'{name}: NoAnswer - no {rdtype} record found')
            except dns.resolver.NoNameservers:
                verbose.debug(f'{name}: NoNameservers - authoritative servers are unreachable')
            except dns.exception.Timeout:
                timeouts += 1
                if timeouts < DNS_MAX_TIMEOUTS:
                    verbose.debug(
                        f'{name}: Timeout ({timeouts}/{DNS_MAX_TIMEOUTS}) - wait a couple of seconds and repeat'
                    )
                    time.sleep(2)
                    continue
                verbose.debug(f'{name}: Timeout - giving up')
            except dns.exception.DNSException as e:
                verbose.debug(f'{name}: {type(e).__name__} - {e}')
            return None

    @staticmethod
    def _is_reachable(u: models.URL, host: str) -> bool:
        if u.scheme in ('http', 'https'):
            try:
                requests.get(u.url, verify=False, timeout=2)
                return True
            except requests.exceptions.RequestException:
                return False
        try:
            socket.create_connection((host, u.port), timeout=2).close()
            return True
        except OSError:
            return False


DNS_SERVERS = [
    # Google
    '8.8.8.8',
    # Google
    '8.8.4.4',
    # Control D
    '76.76.2.0',
    # Control D
    '76.76.10.0',
    # Quad9
    '9.9.9.9',
    # Quad9
    '149.112.112.112',
    # OpenDNS Home
    '208.67.222.222',
    # OpenDNS Home
    '208.67.220.220',
    # Cloudflare
    '1.1.1.1',
    # Cloudflare
    '1.0.0.1',
    # AdGuard DNS
    '94.140.14.14',
    # AdGuard DNS
    '94.140.15.15',
    # CleanBrowsing
    '185.228.168.9',
    # CleanBrowsing
    '185.228.169.9',
    # Oracle
    '216.146.35.35',
    # Oracle
    '216.146.36.36',
    # Quad101
    '101.101.101.101',
    # Quad101
    '101.102.103.104',
    # Nippon Telegraph and Telephone
    '129.250.35.250',
    # Nippon Telegraph and Telephone
    '129.250.35.251',
]
