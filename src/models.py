import pydantic


class CIDR(pydantic.BaseModel):
    type: str = "cidr"
    cidr: str = ""
    number_of_hosts: int = 0
    visibility: str = ""
    asn_country_code: str = ""
    asn_description: str = ""
    network: str = ""


class IPV4(pydantic.BaseModel):
    type: str = "ipv4"
    ipv4: str = ""
    visibility: str = ""
    asn_country_code: str = ""
    asn_description: str = ""
    network: str = ""
    pingable: bool = False


class FQDN(pydantic.BaseModel):
    fqdn: str = ""
    dns_chain: str = ""
    asn_country_code: str = ""
    asn_description: str = ""
    network: str = ""
    pingable: bool = False
