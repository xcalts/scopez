import pydantic
import ipwhois
import dns.resolver
import requests
import pandas

import ipaddress
import subprocess
import os
import concurrent.futures
import random
import urllib.parse
import time

import models
import verbose


class Analyzer(pydantic.BaseModel):
    """Analyzes raw targets and populates them with additiona information."""

    analyzed_ipv4s: list[models.IPV4] = []
    analyzed_cidrs: list[models.CIDR] = []
    analyzed_fqdns: list[models.FQDN] = []
    analyzed_urls: list[models.URL] = []
    geoip_records: list[models.GeoIPRecord] = []

    def parse_geoip_data(self, geoip_csv_database_filepath: str):
        data_frame = pandas.read_csv(geoip_csv_database_filepath).where(pandas.notnull, None)
        records = data_frame.to_dict(orient="records")

        for r in records:
            self.geoip_records.append(
                models.GeoIPRecord(
                    network=r.get("network"),
                    geoname_id=r.get("geoname_id"),
                    continent_code=r.get("continent_code"),
                    continent_name=r.get("continent_name"),
                    country_iso_code=r.get("country_iso_code"),
                    country_name=r.get("country_name"),
                    is_anonymous_proxy=r.get("is_anonymous_proxy"),
                    is_satellite_provider=r.get("is_satellite_provider"),
                )
            )

    def analyze_ipv4s(self, ipv4s: list[str], no_threads: int) -> None:
        """Analyze the IP addresses (v4) and populate them with information.

        Args:
            ipv4s (list[str]): A list of IP addresses in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            futures = [executor.submit(self._populate_ipv4, ip) for ip in ipv4s]

            for future in concurrent.futures.as_completed(futures):
                ipv4_obj = future.result()
                verbose.normal(ipv4_obj.ipv4)
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
                verbose.normal(cidr_obj.cidr)
                self.analyzed_cidrs.append(cidr_obj)

    def analyze_fqdns(self, fqdns: list[str], no_threads: int) -> None:
        """Analyze the FQDNs and populate them with information.

        Args:
            fqdns (list[str]): A list of FQDNs in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            futures = [executor.submit(self._populate_fqdn, fqdn) for fqdn in fqdns]

            for future in concurrent.futures.as_completed(futures):
                fqdn_obj = future.result()
                verbose.normal(fqdn_obj.fqdn)
                self.analyzed_fqdns.append(fqdn_obj)

    def analyze_urls(self, urls: list[str], no_threads: int) -> None:
        """Analyze the URLS and populate them with information.

        Args:
            urls (list[str]): A list of URLs in raw format.
            no_threads(int): The number of worker threads to run in-parallel.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=no_threads) as executor:
            futures = [executor.submit(self._populate_url, url) for url in urls]

            for future in concurrent.futures.as_completed(futures):
                url_obj = future.result()
                verbose.normal(url_obj.url)
                self.analyzed_urls.append(url_obj)

    def _populate_ipv4(self, ipv4: str) -> models.IPV4:
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
            ipv4_obj.asn_network = rdap.get("network", {}).get("name", "").replace(",", "")
            ipv4_obj.asn_country_code = rdap.get("asn_country_code")
            ipv4_obj.asn_description = rdap.get("asn_description", "").replace(",", "")
        else:
            ipv4_obj.asn_network = "N/A"
            ipv4_obj.asn_country_code = "N/A"
            ipv4_obj.asn_description = "N/A"

        #########
        # GeoIP #
        #########
        if ipv4_obj.visibility == "Public":
            for r in self.geoip_records:
                network = ipaddress.IPv4Network(r.network)

                if ip in network:
                    ipv4_obj.geoip_continent = r.continent_name
                    ipv4_obj.geoip_country = r.country_name
        else:
            ipv4_obj.geoip_continent = "N/A"
            ipv4_obj.geoip_country = "N/A"

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

    def _populate_cidr(self, cidr: str) -> models.CIDR:
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
            cidr_obj.asn_network = rdap.get("network", {}).get("name", "").replace(",", "")
            cidr_obj.asn_country_code = rdap.get("asn_country_code")
            cidr_obj.asn_description = rdap.get("asn_description", "").replace(",", "")
        else:
            cidr_obj.asn_network = "N/A"
            cidr_obj.asn_country_code = "N/A"
            cidr_obj.asn_description = "N/A"

        #########
        # GeoIP #
        #########
        if cidr_obj.visibility == "Public":
            for r in self.geoip_records:
                if cidr_obj.asn_network == r.network:
                    cidr_obj.geoip_continent = r.continent_name
                    cidr_obj.geoip_country = r.country_name
        else:
            cidr_obj.geoip_continent = "N/A"
            cidr_obj.geoip_country = "N/A"

        return cidr_obj

    def _populate_fqdn(self, fqdn: str) -> models.FQDN:
        ######################################################################################
        # Process                                                                            #
        # ---                                                                                #
        # Notes:                                                                             #
        # - We need to use different DNS every time otherwise we trigger a DOS response.     #
        # - A FQDN can point only to a *single* CNAME (RFC 1034 & RFC 2181).                 #
        # - A FQDN can point to multiple IP addresses (Load-Balancing).                      #
        # - A FQDN cannot have a CNAME and A/AAA records at the same time.                   #
        # Code:                                                                              #
        # - Keep a list of FQDNs to resolve.                                                 #
        # - Ask DNS server for CNAME records of FQDN.                                        #
        # - If there is a CNAME record, append it in the list of FQDNs to resolve.           #
        #    - else check for A records for the hostname.                                    #
        ######################################################################################
        f = models.FQDN(fqdn=fqdn, dns_chain=[fqdn], destination_ips=[])

        #############################
        # Discover the CNAME Chain. #
        #############################
        while True:
            cname_record = ""
            try:
                answer = dns.resolver.resolve_at(random.choice(DNS_SERVERS), f.dns_chain[-1], "CNAME")
                time.sleep(1)

                for rdap in answer:
                    cname_record = str(rdap.target).rstrip(".")  # Remove the trailing dot.

            except dns.resolver.NXDOMAIN:
                # NXDOMAIN stands for Non-Existent Domain.
                break

            except dns.resolver.NoAnswer:
                # The domain does exist, but the specific DNS record type you're asking for is missing.
                break

            except dns.resolver.LifetimeTimeout:
                # The resolution lifetime expired.
                continue

            f.dns_chain.append(cname_record)

        ############################################################
        # For the last link in the DNS chain, check its A records. #
        ############################################################
        while True:
            try:
                answer = dns.resolver.resolve_at(random.choice(DNS_SERVERS), f.dns_chain[-1], "A")
                time.sleep(1)

                resolved_ips = []
                for rdap in answer:
                    resolved_ips.append(str(rdap.address))

                f.hosts_found = True

                for ip in resolved_ips:
                    ip_obj = self._populate_ipv4(ip)
                    f.destination_ips.append(ip_obj)

                break

            except dns.resolver.NXDOMAIN:
                # NXDOMAIN stands for Non-Existent Domain.
                break

            except dns.resolver.NoAnswer:
                # The domain does exist, but the specific DNS record type you're asking for is missing.
                break

            except dns.resolver.LifetimeTimeout:
                # The resolution lifetime expired.
                continue

        return f

    def _populate_url(self, url: str) -> models.URL:

        parsed_url = urllib.parse.urlparse(url)
        parsed_port = parsed_url.port if parsed_url.port is not None else 443 if parsed_url.scheme == "https" else 80

        u = models.URL(
            url=url,
            scheme=parsed_url.scheme,
            username=parsed_url.username if parsed_url.username is not None else "",
            password=parsed_url.password if parsed_url.password is not None else "",
            port=parsed_port,
            path=parsed_url.path,
        )

        u.fqdn = self._populate_fqdn(parsed_url.hostname)

        ########
        # CURL #
        ########
        try:
            requests.get(u.url, verify=False, timeout=2)
            u.reachable = True
        except requests.exceptions.RequestException:
            u.reachable = False

        return u


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
