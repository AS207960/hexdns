import enum
import ipaddress
from .. import models


@enum.unique
class SPFStatus(enum.Enum):
    NotPresent = enum.auto()
    MultiplePresent = enum.auto()
    PassAll = enum.auto()
    InvalidNet = enum.auto()
    LargeV4Net = enum.auto()
    LargeV6Net = enum.auto()
    AllNotLast = enum.auto()
    OK = enum.auto()


@enum.unique
class DMARCStatus(enum.Enum):
    NotPresent = enum.auto()
    MultiplePresent = enum.auto()
    Invalid = enum.auto()
    NoneRequest = enum.auto()
    PartialPercentage = enum.auto()
    OK = enum.auto()


def check_spf(zone: models.DNSZone) -> SPFStatus:
    records = zone.txtrecord_set.filter(record_name="@")
    records = list(filter(
        lambda r: r.data.startswith("v=spf1 ") or r.data == "v=spf1", records
    ))
    if len(records) == 0:
        return SPFStatus.NotPresent
    elif len(records) > 1:
        return SPFStatus.MultiplePresent

    spf_record = records[0].data[len("v=spf1"):].strip()
    terms = spf_record.split(" ")
    directives = []
    modifiers = []
    for t in terms:
        if t == "":
            continue
        if "=" in t:
            modifiers.append(t.split("=", 1))
        else:
            qualifier = "+"
            if t[0] == "+":
                t = t[1:]
            elif t[0] == "-":
                t = t[1:]
                qualifier = "-"
            elif t[0] == "?":
                t = t[1:]
                qualifier = "?"
            elif t[0] == "~":
                t = t[1:]
                qualifier = "~"
            directives.append((qualifier, t))

    if len(directives) == 0:
        if not any(m[0] == "redirect" for m in modifiers):
            return SPFStatus.AllNotLast

    for i, (q, d) in enumerate(directives):
        if d == "all":
            if q == "+" or q == "?":
                return SPFStatus.PassAll
            if i != len(directives) - 1:
                return SPFStatus.AllNotLast

        if d.startswith("ip4:"):
            try:
                net = ipaddress.IPv4Network(d[len("ip4:"):])
            except ValueError:
                return SPFStatus.InvalidNet

            if net.prefixlen < 14:
                return SPFStatus.LargeV4Net

        if d.startswith("ip6:"):
            try:
                net = ipaddress.IPv6Network(d[len("ip6:"):])
            except ValueError:
                return SPFStatus.InvalidNet

            if net.prefixlen < 32:
                return SPFStatus.LargeV6Net

    return SPFStatus.OK


def check_dmarc(zone: models.DNSZone) -> DMARCStatus:
    records = list(zone.txtrecord_set.filter(record_name="_dmarc"))
    if len(records) == 0:
        return DMARCStatus.NotPresent
    elif len(records) > 1:
        return DMARCStatus.MultiplePresent

    dmarc_record = records[0].data.strip()
    record_parts = list(map(
        lambda t: t.split("=", 1),
        filter(
            lambda p: bool(p.strip()),
            dmarc_record.split(";")
        )
    ))
    tags = []
    for t in record_parts:
        if len(t) != 2:
            return DMARCStatus.Invalid
        tags.append((t[0].strip(), t[1].strip()))

    if len(tags) == 0:
        return DMARCStatus.Invalid
    v_tag = tags.pop(0)
    if v_tag[0] != "v" or v_tag[1] != "DMARC1":
        return DMARCStatus.Invalid

    if len(tags) == 0:
        return DMARCStatus.Invalid
    p_tag = tags.pop(0)
    if p_tag[0] != "p":
        return DMARCStatus.Invalid
    if p_tag[1] == "none":
        return DMARCStatus.NoneRequest
    elif not (p_tag[1] == "quarantine" or p_tag[1] == "reject"):
        return DMARCStatus.Invalid

    pct_tag = next(filter(lambda t: t[0] == "pct", tags), None)
    if pct_tag:
        if pct_tag[1] != "100":
            return DMARCStatus.PartialPercentage

    return DMARCStatus.OK
