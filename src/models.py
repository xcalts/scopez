import pydantic
import rich.table

import verbose


class CIDR(pydantic.BaseModel):
    cidr: str = ""
    number_of_hosts: int = 0
    visibility: str = ""
    network: str = ""
    asn_country_code: str = ""
    asn_description: str = ""
