import requests

from django.conf import settings

URL_ROOT = "https://dnsnodeapi.netnod.se/apiv3"
PRODUCT = "standard-europe-a"
PRIMARY_SERVERS = [{
    "ip": "2a0e:1cc1:1::1:1b",
    "tsig": "netnod-cyfyngedig-1."
}, {
    "ip": "2001:678:fc8:2::18",
    "tsig": "netnod-cyfyngedig-1."
}, {
    "ip": "2001:678:fc8:2::19",
    "tsig": "netnod-cyfyngedig-1."
}, {
    "ip": "2001:678:fc8:2::1a",
    "tsig": "netnod-cyfyngedig-1."
}, {
    "ip": "2001:678:fc8:2::1b",
    "tsig": "netnod-cyfyngedig-1."
}]


def check_zone_registered(zone_name: str) -> bool:
    r = requests.get(f"{URL_ROOT}/zones/{zone_name}", headers={
        "Authorization": f"Token {settings.NETNOD_API_KEY}"
    })
    if r.status_code == 404:
        return False
    r.raise_for_status()
    return True


def register_zone(zone_name: str, end_user: str):
    requests.post(f"{URL_ROOT}/zones/", headers={
        "Authorization": f"Token {settings.NETNOD_API_KEY}"
    }, json={
        "name": zone_name,
        "masters": PRIMARY_SERVERS,
        "product": PRODUCT,
        "endcustomer": end_user
    }).raise_for_status()


def deregister_zone(zone_name: str):
    requests.delete(f"{URL_ROOT}/zones/{zone_name}", headers={
        "Authorization": f"Token {settings.NETNOD_API_KEY}"
    }).raise_for_status()

