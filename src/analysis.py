import pydantic
import ipwhois
import dns.resolver
import requests

import ipaddress
import subprocess
import os
import concurrent.futures
import random
import urllib.parse

import models
import print
import verbose


class Analyzer(pydantic.BaseModel):
    """Analyzes raw targets and populates them with additiona information."""

    analyzed_ipv4s: list[models.IPV4] = []
    analyzed_cidrs: list[models.CIDR] = []
    analyzed_fqdns: list[models.FQDN] = []
    analyzed_urls: list[models.URL] = []

    def analyze_ipv4s(self, ipv4s: list[str], no_threads: int) -> None:
        """Analyze the IP addresses (v4) and populate them with information.

        Args:
            ipv4s (list[str]): A list of IP addresses in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            futures = [executor.submit(self._process_ipv4, ipv4) for ipv4 in ipv4s]

            for future in concurrent.futures.as_completed(futures):
                ipv4_obj = future.result()
                self.analyzed_ipv4s.append(ipv4_obj)

    def analyze_cidrs(self, cidrs: list[str], no_threads: int) -> None:
        """Analyze the CIDR IP addresses (v4) and populate them with information.

        Args:
            cidrs (list[str]): A list of CIDR IP addresses in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            futures = [executor.submit(self._process_cidr, cidr) for cidr in cidrs]

            for future in concurrent.futures.as_completed(futures):
                cidr_obj = future.result()
                self.analyzed_cidrs.append(cidr_obj)

    def analyze_fqdns(self, fqdns: list[str], no_threads: int) -> None:
        """Analyze the FQDNs and populate them with information.

        Args:
            fqdns (list[str]): A list of FQDNs in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            futures = [executor.submit(self._process_fqdn, fqdn) for fqdn in fqdns]

            for future in concurrent.futures.as_completed(futures):
                fqdn_objs = future.result()
                self.analyzed_fqdns.extend(fqdn_objs)

    def analyze_urls(self, urls: list[str], no_threads: int) -> None:
        """Analyze the URLS and populate them with information.

        Args:
            urls (list[str]): A list of URLs in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            futures = [executor.submit(self._process_url, url) for url in urls]

            for future in concurrent.futures.as_completed(futures):
                url_objs = future.result()
                self.analyzed_urls.extend(url_objs)

    def _process_ipv4(self, ipv4: str) -> models.IPV4:
        verbose.normal(ipv4)
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

        ########
        # RDAP #
        ########
        if ipv4_obj.visibility == "Public":
            whois = ipwhois.IPWhois(ipv4_obj.ipv4)
            rdap = whois.lookup_rdap(depth=1) or {}
            ipv4_obj.network = rdap.get("network", {}).get("name", "").replace(",", "")
            ipv4_obj.asn_country_code = rdap.get("asn_country_code")
            ipv4_obj.asn_description = rdap.get("asn_description", "").replace(",", "")
        else:
            ipv4_obj.network = "N/A"
            ipv4_obj.asn_country_code = "N/A"
            ipv4_obj.asn_description = "N/A"

        ########
        # Ping #
        ########
        if ipv4_obj.visibility == "Public":
            param = "-n" if os.sys.platform.lower() == "win32" else "-c"
            command = ["ping", param, "1", "-i", "0.2", ipv4]
            pingable = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
            ipv4_obj.pingable = pingable
        else:
            ipv4_obj.pingable = False

        return ipv4_obj

    def _process_cidr(self, cidr: str) -> models.CIDR:
        verbose.normal(cidr)
        cidr_obj = models.CIDR()
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

        ########
        # RDAP #
        ########
        if cidr_obj.visibility == "Public":
            ip = cidr.split("/")[0]
            whois = ipwhois.IPWhois(ip)
            rdap = whois.lookup_rdap(depth=1) or {}
            cidr_obj.network = rdap.get("network", {}).get("name", "").replace(",", "")
            cidr_obj.asn_country_code = rdap.get("asn_country_code")
            cidr_obj.asn_description = rdap.get("asn_description", "").replace(",", "")
        else:
            cidr_obj.network = "N/A"
            cidr_obj.asn_country_code = "N/A"
            cidr_obj.asn_description = "N/A"

        return cidr_obj

    def _process_fqdn(self, fqdn: str) -> list[models.FQDN]:
        verbose.normal(fqdn)
        _results: list[models.FQDN] = []
        _cname: str = ""
        _ips: list[str] = []
        _dns_server = random.choice(DNS_SERVERS)

        ######################################################################################
        # DNS                                                                                #
        # ---                                                                                #
        # Note: We need to use different DNS every time otherwise we trigger a DOS response. #
        # 1. Check if there are CNAME records for hostname.                                  #
        #    - If there CNAME records, then check for A records for the found CNAME          #
        #    - else check for A records for the hostname.                                    #
        ######################################################################################
        try:
            cname_records = dns.resolver.resolve_at(_dns_server, fqdn, "CNAME")
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
            _results.append(fqdn_obj)
            return _results
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
            _results.append(fqdn_obj)
            return _results

        if _cname != "":
            try:
                a_records = dns.resolver.resolve_at(_dns_server, _cname, "A")

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
                    command = ["ping", param, "1", "-i 0.2", fqdn]
                    fqdn_obj.pingable = subprocess.call(command, stdout=subprocess.DEVNULL) == 0

                    _results.append(fqdn_obj)

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
                _results.append(fqdn_obj)
                return _results
        else:
            try:
                a_records = dns.resolver.resolve_at(_dns_server, fqdn, "A")

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
                    command = ["ping", param, "1", "-i 0.2", fqdn]
                    fqdn_obj.pingable = subprocess.call(command, stdout=subprocess.DEVNULL) == 0

                    _results.append(fqdn_obj)

                return _results

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
                _results.append(fqdn_obj)
                return _results

    def _process_url(self, url: str) -> list[models.URL]:
        verbose.normal(url)
        _results: list[models.URL] = []
        _cname: str = ""
        _ips: list[str] = []
        _dns_server = random.choice(DNS_SERVERS)

        parsed_url = urllib.parse.urlparse(url)
        parsed_port = parsed_url.port if parsed_url.port is not None else 443 if parsed_url.scheme == "https" else 80

        ######################################################################################
        # DNS                                                                                #
        # ---                                                                                #
        # Note: We need to use different DNS every time otherwise we trigger a DOS response. #
        # 1. Check if there are CNAME records for hostname.                                  #
        #    - If there CNAME records, then check for A records for the found CNAME          #
        #    - else check for A records for the hostname.                                    #
        ######################################################################################
        try:
            cname_records = dns.resolver.resolve_at(_dns_server, parsed_url.hostname, "CNAME")
            for rdap in cname_records:
                _cname = str(rdap.target).rstrip(".")  # Remove the trailing dot.
        except dns.resolver.NoNameservers:
            url_obj = models.URL(
                url=parsed_url.geturl(),
                scheme=parsed_url.scheme,
                username=parsed_url.username if parsed_url.username is not None else "",
                password=parsed_url.password if parsed_url.password is not None else "",
                fqdn=parsed_url.hostname,
                port=parsed_port,
                path=parsed_url.path,
                dns_chain=f"{parsed_url.hostname} > NotFound",
                asn_country_code="N/A",
                asn_description="N/A",
                network="N/A",
                pingable=False,
            )
            _results.append(url_obj)
            return _results
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            url_obj = models.URL(
                url=parsed_url.geturl(),
                scheme=parsed_url.scheme,
                username=parsed_url.username if parsed_url.username is not None else "",
                password=parsed_url.password if parsed_url.password is not None else "",
                fqdn=parsed_url.hostname,
                port=parsed_port,
                path=parsed_url.path,
                dns_chain=f"{parsed_url.hostname} > NotExist",
                asn_country_code="N/A",
                asn_description="N/A",
                network="N/A",
                pingable=False,
            )
            _results.append(url_obj)
            return _results

        if _cname != "":
            try:
                a_records = dns.resolver.resolve_at(_dns_server, _cname, "A")

                for rdap in a_records:
                    _ips.append(str(rdap.address))

                for ip in _ips:
                    url_obj = models.URL(
                        url=parsed_url.geturl(),
                        scheme=parsed_url.scheme,
                        username=parsed_url.username if parsed_url.username is not None else "",
                        password=parsed_url.password if parsed_url.password is not None else "",
                        fqdn=parsed_url.hostname,
                        port=parsed_port,
                        path=parsed_url.path,
                    )

                    ########
                    # RDAP #
                    ########
                    whois = ipwhois.IPWhois(ip)
                    rdap = whois.lookup_rdap(depth=1)
                    url_obj.dns_chain = f"{parsed_url.hostname} > {_cname} > {ip}"
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
                        requests.get(url_obj.url, verify=False, timeout=2)
                        url_obj.reachable = True
                    except requests.exceptions.RequestException:
                        url_obj.reachable = False

                    _results.append(url_obj)

            except dns.resolver.NoAnswer:
                pass

            except dns.resolver.NXDOMAIN:
                url_obj = models.URL(
                    url=parsed_url.geturl(),
                    scheme=parsed_url.scheme,
                    username=parsed_url.username if parsed_url.username is not None else "",
                    password=parsed_url.password if parsed_url.password is not None else "",
                    fqdn=parsed_url.hostname,
                    port=parsed_port,
                    path=parsed_url.path,
                    dns_chain=f"{url} > {_cname} > NotFound",
                    asn_country_code="N/A",
                    asn_description="N/A",
                    network="N/A",
                    pingable=False,
                )
                _results.append(url_obj)
                return _results
        else:
            try:
                a_records = dns.resolver.resolve_at(_dns_server, parsed_url.hostname, "A")

                for rdap in a_records:
                    _ips.append(str(rdap.address))

                for ip in _ips:
                    url_obj = models.URL(
                        url=parsed_url.geturl(),
                        scheme=parsed_url.scheme,
                        username=parsed_url.username if parsed_url.username is not None else "",
                        password=parsed_url.password if parsed_url.password is not None else "",
                        fqdn=parsed_url.hostname,
                        port=parsed_port,
                        path=parsed_url.path,
                    )

                    ########
                    # RDAP #
                    ########
                    whois = ipwhois.IPWhois(ip)
                    rdap = whois.lookup_rdap(depth=1)
                    url_obj.dns_chain = f"{parsed_url.hostname} > {ip}"
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
                        requests.get(url_obj.url, verify=False, timeout=2)
                        url_obj.reachable = True
                    except requests.exceptions.RequestException:
                        url_obj.reachable = False

                    _results.append(url_obj)

                return _results

            except dns.resolver.NoAnswer:
                pass

            except dns.resolver.NXDOMAIN:
                url_obj = models.URL(
                    url=parsed_url.geturl(),
                    scheme=parsed_url.scheme,
                    username=parsed_url.username if parsed_url.username is not None else "",
                    password=parsed_url.password if parsed_url.password is not None else "",
                    fqdn=parsed_url.hostname,
                    port=parsed_port,
                    path=parsed_url.path,
                    dns_chain=f"{parsed_url.hostname} > NotFound",
                    asn_country_code="N/A",
                    asn_description="N/A",
                    network="N/A",
                    pingable=False,
                )
                _results.append(url_obj)
                return _results


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
    # Oracle
    "216.146.35.35",
    # Oracle
    "216.146.36.36",
    # Quad101
    "101.101.101.101",
    # Quad101
    "101.102.103.104",
    # Nippon Telegraph and Telephone
    "129.250.35.250",
    # Nippon Telegraph and Telephone
    "129.250.35.251",
]
