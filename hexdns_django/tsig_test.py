import dns.query
import dns.update
import dns.name
import dns.tsig
import base64
import hmac
import time

msg = dns.update.UpdateMessage(zone="neveripv4.com",)


class CTX:
    def __init__(self, key):
        self.hmac_context = hmac.new(key, digestmod="sha256")
        self.data = bytearray()

    def update(self, data):
        self.data += data
        return self.hmac_context.update(data)

    def digest(self):
        digest = self.hmac_context.digest()
        return digest


# print(base64.b64decode("DgGZeGow1ZaclAQI3yJJmUnn9EhOCDnkwOjd/DApjeG7til2/TXykRTZV9ndFGHa4dbrnezlCt52NGOc6HWHnQ=="))

ctxes = []


def get_ctx(_):
    ctx = CTX(base64.b64decode("DgGZeGow1ZaclAQI3yJJmUnn9EhOCDnkwOjd/DApjeG7til2/TXykRTZV9ndFGHa4dbrnezlCt52NGOc6HWHnQ=="))
    ctxes.append(ctx)
    return ctx

dns.tsig.get_context = get_ctx

msg.use_tsig(
    keyname="hexdns_zoneupdatesecret_804aed5c15954913aa6fe7b3fb934710",
    keyring=dns.tsig.Key(
        name="hexdns_zoneupdatesecret_804aed5c15954913aa6fe7b3fb934710.neveripv4.com",
        secret="DgGZeGow1ZaclAQI3yJJmUnn9EhOCDnkwOjd/DApjeG7til2/TXykRTZV9ndFGHa4dbrnezlCt52NGOc6HWHnQ=="
    ),
)

msg.add("_acme_challenge.a.neveripv4.com", 3600, "txt", "abc")

# print(msg.to_wire())

try:
    r = dns.query.udp(msg, '127.0.0.1')
except Exception as e:
    print(e)

print(list(map(lambda c: c.data, ctxes)))
# print(r)
