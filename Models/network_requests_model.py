from dataclasses import dataclass


@dataclass
class NetworkRequestModel:
    domain_dst: str
    ip_dst: str
    ip_src: str
    domain_src: str
