import typing
import ipaddress
import dnslib
from django.core.exceptions import ValidationError


def svcb_fetch_port_blocking(port: int):
    if port in (
            1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104,
            109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515,
            526, 530, 531, 532, 540, 548, 554, 556, 563, 601, 636, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 5060,
            5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6697, 10080,
    ):
        return True
    else:
        return False


def is_item_allowed_char(char: int):
    if 0x00 <= char <= 0x2b or 0x2d <= char <= 0x5b or 0x5d <= char <= 0xff:
        return True
    else:
        return False


def is_non_special_char(char: int):
    if char == 0x21 or 0x23 <= char <= 0x27 or 0x2a <= char <= 0x3a or 0x3c <= char <= 0x5b or 0x5d <= char <= 0x7e:
        return True
    else:
        return False


def is_non_digit_char(char: int):
    if 0x21 <= char <= 0x2f or 0x3a <= char <= 0x7e:
        return True
    else:
        return False


def is_digit_char(char: int):
    if 0x30 <= char <= 0x39:
        return True
    else:
        return False


def is_wsp(char: int):
    # Space and tab
    if char == 32 or char == 9:
        return True
    else:
        return False


def decode_escaped(data: bytearray):
    try:
        f = data.pop(0)
        if is_non_digit_char(f):
            return f
        else:
            d2 = data.pop(0)
            d3 = data.pop(0)
            if not (is_digit_char(f) and is_digit_char(d2) and is_digit_char(d3)):
                raise ValidationError(f"Invalid escape value")
            val = (f-0x30) * 100 + (d2 - 0x30) * 10 + (d3 - 0x30)
            if val > 255:
                raise ValidationError(f"Escaped byte {val} too large")
            return val
    except IndexError:
        raise ValidationError("Unterminated escape sequence")


def decode_contiguous_str(data: bytearray, allow_space=False):
    out = bytearray()
    try:
        while True:
            c = data.pop(0)
            if c == 92:
                out.append(decode_escaped(data))
            elif is_non_special_char(c) or (c == 32 and allow_space):
                out.append(c)
            else:
                data.insert(0, c)
                return out
    except IndexError:
        return out


def decode_char_str(data: bytearray):
    if data[0] == 34:
        data.pop(0)
        out = decode_contiguous_str(data, allow_space=True)
        if not len(data) or data.pop(0) != 34:
            raise ValidationError("Unterminated quoted string")
        return out
    else:
        return decode_contiguous_str(data)


def decode_svcb_param_key(data: bytearray):
    out = []
    try:
        while True:
            c = data.pop(0)
            # - char
            if 0x61 <= c <= 0x7a or is_digit_char(c) or c == 45:
                out.append(c)
            else:
                data.insert(0, c)
                return out
    except IndexError:
        return out


def decode_escaped_item(data: bytearray):
    out = bytearray()
    try:
        while True:
            c = data.pop(0)
            if is_item_allowed_char(c):
                out.append(c)
            elif c == 92:
                try:
                    c = data.pop(0)
                except IndexError:
                    raise ValidationError("Unterminated escape sequence")
                if c in (92, 44):
                    out.append(c)
                else:
                    raise ValidationError(f"Invalid escape character: {chr(c)}")
            else:
                data.insert(0, c)
                break
    except IndexError:
        pass
    return bytes(out)


def decode_svcb_comma_list(data: bytearray):
    out = []
    while True:
        out.append(decode_escaped_item(data))

        try:
            c = data.pop(0)
        except IndexError:
            break

        if c != 44:
            raise ValidationError(f"Invalid list character: {chr(c)}")

    return out


def decode_svcb_param_list(value: str):
    params = {}
    data = bytearray(value.encode("utf8"))
    while True:
        while is_wsp(data[0]):
            data.pop(0)
        key = bytes(decode_svcb_param_key(data)).decode("ascii")
        if not len(data):
            params[key] = bytearray()
            break
        c = data.pop(0)
        # = char
        if c == 61:
            params[key] = decode_char_str(data)
        # space char
        elif is_wsp(c):
            params[key] = bytearray()
        else:
            raise ValidationError("Invalid parameter separation")
        if not len(data):
            break

    out = []
    for key, data in params.items():
        try:
            out.append(SVCBParam(key, OctetParamData(data)))
        except ValueError as e:
            raise ValidationError(f"Invalid SVCB parameter: {e}")
    return SVCBParamList(out)


class SVCBParam:
    PARAM_MAPPING = {
        "mandatory": 0,
        "alpn": 1,
        "no-default-alpn": 2,
        "port": 3,
        "ipv4hint": 4,
        "ech": 5,
        "ipv6hint": 6
    }

    @classmethod
    def param_id_to_name(cls, param: int):
        for k, v in cls.PARAM_MAPPING.items():
            if v == param:
                return k
        return f"key{param}"

    def __init__(self, key: typing.Union[str, int], data):
        if isinstance(key, str):
            if key in self.PARAM_MAPPING:
                key_id = self.PARAM_MAPPING[key]
            elif key.startswith("key"):
                key_id = int(key[3:])
            else:
                raise ValueError("unrecognised key")
        elif isinstance(key, int):
            key_id = key
        else:
            raise ValueError("unrecognised key")

        self.key = key_id
        self.data = data

    def pack(self, buffer: dnslib.DNSBuffer):
        data = dnslib.DNSBuffer()
        self.data.pack(data)
        if len(data) > 65535:
            raise ValueError("parameter data too long")
        buffer.pack("!HH", self.key, len(data))
        buffer.append(data.data)

    def __repr__(self):
        if isinstance(self.data, NullParamData):
            return SVCBParam.param_id_to_name(self.key)

        return f"{SVCBParam.param_id_to_name(self.key)}={repr(self.data)}"


class SVCBParamList:
    def __init__(self, params: typing.List[SVCBParam]):
        self.params = params

    def pack(self, buffer: dnslib.DNSBuffer):
        sorted_keys = sorted(self.params, key=lambda p: p.key)
        for key in sorted_keys:
            key.pack(buffer)

    def __contains__(self, key):
        if key in SVCBParam.PARAM_MAPPING:
            key = SVCBParam.PARAM_MAPPING[key]
        for v in self.params:
            if v.key == key:
                return True
        return False

    def __getitem__(self, key):
        if key in SVCBParam.PARAM_MAPPING:
            key = SVCBParam.PARAM_MAPPING[key]
        for v in self.params:
            if v.key == key:
                return v

    def __repr__(self):
        return ' '.join(map(repr, self.params))


class SVCB(dnslib.RD):
    attrs = ('priority', 'target', 'params')

    def __init__(self, priority: int, target: dnslib.DNSLabel, params: SVCBParamList):
        self.priority = priority
        self.target = target
        self.params = params

    def pack(self, buffer: dnslib.DNSBuffer):
        buffer.pack("!H", self.priority)
        buffer.encode_name_nocompress(self.target)
        self.params.pack(buffer)

    def __repr__(self):
        return f"{self.priority} {self.target} {repr(self.params)}"


class NullParamData:
    def pack(self, buf: dnslib.DNSBuffer):
        pass

    def __repr__(self):
        return "null"


class OctetParamData:
    def __init__(self, data: bytes):
        self.data = data

    def pack(self, buf: dnslib.DNSBuffer):
        buf.append(self.data)

    def __repr__(self):
        out = ""
        for b in self.data:
            if b <= 127:
                out += chr(b)
            else:
                out += f"\\{b}"
        return out


class MandatoryData:
    def __init__(self, params: typing.List[int]):
        self.params = params

    def pack(self, buf: dnslib.DNSBuffer):
        for p in self.params:
            buf.pack("!H", p)

    def __repr__(self):
        return ','.join(SVCBParam.param_id_to_name(p) for p in self.params)


class ALPNData:
    def __init__(self, alpns: typing.List[bytes]):
        for v in alpns:
            if len(v) > 255:
                raise ValidationError(f"Value '{v}' is longer than the maximum of 255 bytes")

        self.alpns = alpns

    @classmethod
    def from_str(cls, data: str):
        data = bytearray(data.encode("utf8"))
        value = decode_char_str(data)
        if len(data):
            raise ValidationError("Left over data after decoding ALPN list")

        elms = decode_svcb_comma_list(value)
        return cls(elms)

    def pack(self, buf: dnslib.DNSBuffer):
        for p in self.alpns:
            buf.pack("!B", len(p))
            buf.append(p)

    def __repr__(self):
        return ','.join(v.decode() for v in self.alpns)


class IPv4Data:
    def __init__(self, addrs: typing.List[ipaddress.IPv4Address]):
        self.addrs = addrs

    @classmethod
    def from_str(cls, data: str):
        data = bytearray(data.encode("utf8"))
        value = decode_char_str(data)
        if len(data):
            raise ValidationError("Left over data after decoding IPv4 list")

        elms = decode_svcb_comma_list(value)
        addrs = []
        for v in elms:
            try:
                v_str = v.decode("utf8")
            except UnicodeDecodeError:
                raise ValidationError(f"Value '{v}' is not valid Unicode")
            try:
                addrs.append(ipaddress.IPv4Address(v_str))
            except ipaddress.AddressValueError as e:
                raise ValidationError(f"Invalid address: {str(e)}")

        return cls(addrs)

    def pack(self, buf: dnslib.DNSBuffer):
        for a in self.addrs:
            buf.append(a.packed)

    def __repr__(self):
        return ','.join(str(v) for v in self.addrs)


class IPv6Data:
    def __init__(self, addrs: typing.List[ipaddress.IPv6Address]):
        self.addrs = addrs

    @classmethod
    def from_str(cls, data: str):
        data = bytearray(data.encode("utf8"))
        value = decode_char_str(data)
        if len(data):
            raise ValidationError("Left over data after decoding IPv4 list")

        elms = decode_svcb_comma_list(value)
        addrs = []
        for v in elms:
            try:
                v_str = v.decode("utf8")
            except UnicodeDecodeError:
                raise ValidationError(f"Value '{v}' is not valid Unicode")
            try:
                addrs.append(ipaddress.IPv6Address(v_str))
            except ipaddress.AddressValueError as e:
                raise ValidationError(f"Invalid address: {str(e)}")

        return cls(addrs)

    def pack(self, buf: dnslib.DNSBuffer):
        for a in self.addrs:
            buf.append(a.packed)

    def __repr__(self):
        return ','.join(str(v) for v in self.addrs)
