"""Request models. Everything that ends up in the iptables script is strictly validated here."""
import ipaddress
import re
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

NAME_RE = re.compile(r"^[A-Za-z0-9 _.:-]{1,64}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}\+?$")
PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def _name(v: str) -> str:
    v = v.strip()
    if not NAME_RE.match(v):
        raise ValueError("1-64 characters: letters, digits, space, _ . : -")
    return v


class NetworkIn(BaseModel):
    name: str
    cidr: Optional[str] = None
    interface: Optional[str] = None
    description: str = Field("", max_length=500)

    check_name = field_validator("name")(_name)

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        net = ipaddress.ip_network(v.strip(), strict=False)
        if net.version != 4:
            raise ValueError("only IPv4 networks are supported")
        return str(net)

    @field_validator("interface")
    @classmethod
    def _iface(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        v = v.strip()
        if not IFACE_RE.match(v):
            raise ValueError("invalid interface name (e.g. eth0, br-lan, veth+)")
        return v

    @model_validator(mode="after")
    def _cidr_or_iface(self):
        if not self.cidr and not self.interface:
            raise ValueError("set a CIDR, an interface, or both")
        return self


class ServiceIn(BaseModel):
    name: str
    protocol: Literal["tcp", "udp", "tcp+udp", "icmp", "any"]
    ports: str = ""
    description: str = Field("", max_length=500)

    check_name = field_validator("name")(_name)

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str) -> str:
        out = []
        for part in v.replace(" ", "").split(","):
            if not part:
                continue
            m = PORT_RE.match(part)
            if not m:
                raise ValueError(f"invalid port '{part}' (use 22, 80,443 or 8000-8010)")
            lo = int(m[1])
            hi = int(m[2]) if m[2] else lo
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or hi < lo:
                raise ValueError(f"invalid port range '{part}'")
            out.append(f"{lo}-{hi}" if hi != lo else str(lo))
        return ",".join(dict.fromkeys(out))

    @model_validator(mode="after")
    def _ports_need_l4(self):
        if self.protocol in ("icmp", "any") and self.ports:
            raise ValueError("ports are only valid for tcp / udp")
        return self


class RuleIn(BaseModel):
    name: str
    chain: Literal["input", "forward"]
    src_network_id: Optional[int] = None
    dst_network_id: Optional[int] = None
    service_id: Optional[int] = None
    action: Literal["ACCEPT", "DROP", "REJECT"] = "ACCEPT"
    log: bool = False
    enabled: bool = True
    comment: str = Field("", max_length=500)

    check_name = field_validator("name")(_name)


class SettingsIn(BaseModel):
    allow_established: bool = True
    input_default: Literal["RETURN", "DROP"] = "RETURN"
    forward_default: Literal["RETURN", "DROP"] = "RETURN"
    confirm_timeout: int = Field(60, ge=0, le=600)


class ReorderIn(BaseModel):
    ids: list[int]
