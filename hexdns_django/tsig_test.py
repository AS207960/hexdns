import dns.query
import dns.update
import dns.name
import dns.tsig
import base64
import hmac
import time

msg = dns.update.UpdateMessage(zone="pfuschwerk.de.",)


class CTX:
    def __init__(self, key):
        self.hmac_context = hmac.new(key, digestmod="sha512")
        self.data = bytearray()

    def update(self, data):
        self.data += data
        return self.hmac_context.update(data)

    def digest(self):
        digest = self.hmac_context.digest()
        return digest

ctxes = []


def get_ctx(_):
    ctx = CTX(base64.b64decode(""))
    ctxes.append(ctx)
    return ctx

dns.tsig.get_context = get_ctx

msg.use_tsig(
    keyname="hexdns_zoneupdatesecret_3fcae682d3a549d9aea5f831ab04352b",
    keyring=dns.tsig.Key(
        name="hexdns_zoneupdatesecret_3fcae682d3a549d9aea5f831ab04352b.pfuschwerk.de.",
        secret="",
    ),
    algorithm="hmac-sha512",
)

msg.add("gate.servers.pfuschwerk.de.", 60, "txt", "\"this is test two\"")
msg.add("gate.servers.pfuschwerk.de.", 60, "txt", "\"this is test three\"")

# print(msg.to_wire())

try:
    r = dns.query.udp(msg, '127.0.0.1')
except Exception as e:
    print(e)

print(list(map(lambda c: c.data, ctxes)))
# print(r)
