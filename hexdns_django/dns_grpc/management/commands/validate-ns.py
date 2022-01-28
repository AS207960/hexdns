from django.core.management.base import BaseCommand
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from dns_grpc import models, views
import keycloak.exceptions
import random
import retry
import dnslib

WANTED_NS = [dnslib.DNSLabel('ns1.as207960.net'), dnslib.DNSLabel('ns2.as207960.net')]


def mail_valid(user, zone):
    feedback_url = views.utils.get_feedback_url(
        f"HexDNS for {zone.zone_root}", zone.id
    )

    context = {
        "name": user.first_name,
        "zone": zone,
        "feedback_url": feedback_url
    }
    html_content = render_to_string("dns_email/valid.html", context)
    txt_content = render_to_string("dns_email/valid.txt", context)

    email = EmailMultiAlternatives(
        subject='HexDNS Zone Activated',
        body=txt_content,
        to=[user.email],
        bcc=['email-log@as207960.net'],
        reply_to=['Glauca Support <hello@glauca.digital>']
    )
    email.attach_alternative(html_content, "text/html")
    email.send()


def mail_invalid(user, zone):
    context = {
        "name": user.first_name,
        "zone": zone
    }
    html_content = render_to_string("dns_email/invalid.html", context)
    txt_content = render_to_string("dns_email/invalid.txt", context)

    email = EmailMultiAlternatives(
        subject='HexDNS Zone Inactive',
        body=txt_content,
        to=[user.email],
        bcc=['email-log@as207960.net'],
        reply_to=['Glauca Support <hello@glauca.digital>']
    )
    email.attach_alternative(html_content, "text/html")
    email.send()


@retry.retry(tries=5)
def lookup_ns(label, server, port=53):
    question = dnslib.DNSRecord(q=dnslib.DNSQuestion(label, dnslib.QTYPE.NS))
    res_pkt = question.send(server, port=port, ipv6=True, tcp=False, timeout=5)
    res = dnslib.DNSRecord.parse(res_pkt)

    name_servers = list(
        filter(
            lambda r: r.rtype == dnslib.QTYPE.NS and r.rclass == dnslib.CLASS.IN,
            res.auth if len(res.auth) > 0 else res.rr
        )
    )
    if not name_servers:
        return None
    return name_servers


def query_authoritative_ns(domain):
    dns_name = dnslib.DNSLabel(domain)
    ns = lookup_ns(".", settings.RESOLVER_ADDR, port=settings.RESOLVER_PORT)
    use_ns = random.choice(ns)

    last = False
    depth = 1
    while not last:
        cur_dns_name = dnslib.DNSLabel(dns_name.label[-depth:])

        ns = lookup_ns(cur_dns_name, str(use_ns.rdata.label))

        if not ns:
            return None

        use_ns = random.choice(ns)

        if use_ns.rname == dns_name:
            break

        depth += 1

    return ns


class Command(BaseCommand):
    help = 'Checks that every zone is pointed to us'

    @staticmethod
    def increment_zone_fail(zone):
        if zone.active:
            zone.num_check_fails += 1
            if zone.num_check_fails >= 5:
                print(f"Setting {zone} to inactive")
                zone.active = False
                try:
                    mail_invalid(zone.get_user(), zone)
                except keycloak.exceptions.KeycloakClientError as e:
                    print(f"Failed to notify user of status: {e}")
            zone.save()

    def handle(self, *args, **options):
        for zone in list(models.DNSZone.objects.all()) + list(models.SecondaryDNSZone.objects.all()):
            try:
                ns = query_authoritative_ns(zone.zone_root)
            except (dnslib.DNSError, OSError) as e:
                print(f"Cant validate {zone}: {e}")
                continue

            if not ns:
                print(f"{zone} does not exist")
                self.increment_zone_fail(zone)
                continue

            if isinstance(zone, models.DNSZone) and zone.custom_ns.count():
                wanted_ns = [dnslib.DNSLabel(ns.nameserver) for ns in zone.custom_ns.all()]
            else:
                wanted_ns = WANTED_NS

            is_valid = all(any(rr.rdata.label == wns for rr in ns) for wns in wanted_ns)

            if is_valid:
                print(f"{zone} is valid")
                if not zone.active:
                    print(f"Setting {zone} to active")
                zone.active = True
                zone.num_check_fails = 0
                zone.save()
            else:
                print(f"{zone} is invalid")
                self.increment_zone_fail(zone)
