import pydantic
import typing


class CIDR(pydantic.BaseModel):
    type: str = "cidr"
    cidr: str = ""
    number_of_hosts: int = 0
    visibility: str = ""
    asn_country_code: str = ""
    asn_description: str = ""
    asn_network: str = ""
    geoip_continent: str = ""
    geoip_country: str = ""


class IPV4(pydantic.BaseModel):
    type: str = "ipv4"
    ipv4: str = ""
    visibility: str = ""
    asn_country_code: str = ""
    asn_description: str = ""
    asn_network: str = ""
    geoip_continent: str = ""
    geoip_country: str = ""
    pingable: bool = False


class FQDN(pydantic.BaseModel):
    type: str = "fqdn"
    fqdn: str = ""
    dns_chain: list[str] = ""
    hosts_found: bool = False
    
    destination_ips: list[IPV4] = []


class URL(pydantic.BaseModel):
    type: str = "url"
    url: str = ""
    scheme: str = ""
    username: str = ""
    password: str = ""
    port: int = ""
    path: str = ""
    reachable: bool = False
    
    fqdn: FQDN = None


class GeoIPRecord(pydantic.BaseModel):
    network: str
    geoname_id: int
    continent_code: typing.Optional[str]
    continent_name: typing.Optional[str]
    country_iso_code: typing.Optional[str]
    country_name: typing.Optional[str]
    is_anonymous_proxy: int
    is_satellite_provider: int
