import base64
import binascii
import ipaddress
import struct
import math
import secrets
import hashlib
import django_keycloak_auth.clients
import dnslib
import codecs
import sshpubkeys
import socket
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
import as207960_utils.models


class Account(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    subscription_id = models.CharField(max_length=255, blank=True, null=True)
    subscription_active = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user)


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_profile(sender, instance, created, **kwargs):
    if created or not hasattr(instance, "account"):
        Account.objects.create(user=instance)
    instance.account.save()


class DNSZone(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_zone", primary_key=True)
    zone_root = models.CharField(max_length=255, db_index=True)
    last_modified = models.DateTimeField()
    zsk_private = models.TextField(blank=True, null=True)
    charged = models.BooleanField(default=True, blank=True)
    active = models.BooleanField(default=False, blank=True)
    num_check_fails = models.PositiveIntegerField(default=0)
    resource_id = models.UUIDField(null=True, db_index=True)
    cds_disable = models.BooleanField(default=False, blank=True)

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(resource_id__in=as207960_utils.models.get_object_ids(access_token, 'zone', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-zone"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, f"zone", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-zone"
        return as207960_utils.models.eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        self.zone_root = self.zone_root.lower()
        as207960_utils.models.sync_resource_to_keycloak(
            self,
            display_name="Zone", scopes=[
                'view-zone',
                'edit-zone',
                'delete-zone',
            ],
            urn="urn:as207960:hexdns:zone", super_save=super().save, view_name='edit_zone',
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        as207960_utils.models.delete_resource(self.resource_id)

    def get_user(self):
        return as207960_utils.models.get_resource_owner(self.resource_id)

    class Meta:
        verbose_name = "DNS Zone"
        verbose_name_plural = "DNS Zones"

    def __str__(self):
        return self.zone_root


def hex_validator(value):
    try:
        bytes.fromhex(value)
    except ValueError:
        raise ValidationError("Value is not valid hex")


def b64_validator(value):
    try:
        base64.b64decode(value)
    except binascii.Error:
        raise ValidationError("Value is not valid Base64")


class DNSZoneAdditionalCDS(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_zoneadditionalcds", primary_key=True)
    dns_zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE, related_name='additional_cds')
    key_tag = models.SmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(65535)])
    algorithm = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    digest_type = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    digest = models.TextField(validators=[hex_validator])


class DNSZoneAdditionalCDNSKEY(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_zoneadditionalcdnskey", primary_key=True)
    dns_zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE, related_name='additional_cdnskey')
    flags = models.SmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(65535)])
    protocol = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    algorithm = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    public_key = models.TextField(validators=[b64_validator])


def make_update_secret():
    return secrets.token_bytes(64)


class DNSZoneUpdateSecrets(models.Model):
    TYPE_UNLIMITED = "U"
    TYPE_ACME_DNS01 = "D"

    TYPES = (
        (TYPE_UNLIMITED, "Unlimited access"),
        (TYPE_ACME_DNS01, "ACME DNS01 access")
    )

    id = as207960_utils.models.TypedUUIDField("hexdns_zoneupdatesecret", primary_key=True)
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE)
    type = models.CharField(max_length=1, choices=TYPES)
    secret = models.BinaryField(default=make_update_secret)

    def __str__(self):
        return f"{self.id}.{self.zone.zone_root}"

    @property
    def secret_str(self):
        return base64.b64encode(self.secret).decode()


class ReverseDNSZone(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzone", primary_key=True)
    zone_root_address = models.GenericIPAddressField(db_index=True)
    zone_root_prefix = models.PositiveIntegerField(validators=[MaxValueValidator(128)], db_index=True)
    last_modified = models.DateTimeField()
    zsk_private = models.TextField(blank=True, null=True)
    charged = models.BooleanField(default=True, blank=True)
    active = models.BooleanField(default=True, blank=True)
    num_check_fails = models.PositiveIntegerField(default=0)
    resource_id = models.UUIDField(null=True, db_index=True)
    cds_disable = models.BooleanField(default=False, blank=True)

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(
            resource_id__in=as207960_utils.models.get_object_ids(access_token, 'reverse-zone', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-reverse-zone"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, f"reverse-zone", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-reverse-zone"
        return as207960_utils.models.eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        as207960_utils.models.sync_resource_to_keycloak(
            self,
            display_name="Reverse zone", scopes=[
                'view-reverse-zone',
                'edit-reverse-zone',
                'delete-reverse-zone',
            ],
            urn="urn:as207960:hexdns:reverse_zone", super_save=super().save, view_name='edit_rzone',
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        as207960_utils.models.delete_resource(self.resource_id)

    def get_user(self):
        return as207960_utils.models.get_resource_owner(self.resource_id)

    class Meta:
        verbose_name = "Reverse DNS Zone"
        verbose_name_plural = "Reverse DNS Zones"

    def clean(self):
        try:
            ipaddress.ip_network((self.zone_root_address, self.zone_root_prefix))
        except ValueError as e:
            raise ValidationError(str(e))

    @property
    def network(self):
        try:
            return ipaddress.ip_network(
                (self.zone_root_address, self.zone_root_prefix)
            )
        except ValueError:
            return None

    def __str__(self):
        return f"{self.zone_root_address}/{self.zone_root_prefix}"


class ReverseDNSZoneAdditionalCDS(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzoneadditionalcds", primary_key=True)
    dns_zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE, related_name='additional_cds')
    key_tag = models.SmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(65535)])
    algorithm = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    digest_type = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    digest = models.TextField(validators=[hex_validator])


class ReverseDNSZoneAdditionalCDNSKEY(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzoneadditionalcdnskey", primary_key=True)
    dns_zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE, related_name='additional_cdnskey')
    flags = models.SmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(65535)])
    protocol = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    algorithm = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    public_key = models.TextField(validators=[b64_validator])


class SecondaryDNSZone(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_szone", primary_key=True)
    zone_root = models.CharField(max_length=255, db_index=True)
    serial = models.PositiveIntegerField(null=True)
    primary = models.CharField(max_length=255)
    charged = models.BooleanField(default=True, blank=True)
    active = models.BooleanField(default=False, blank=True)
    error = models.BooleanField(default=False, blank=True)
    num_check_fails = models.PositiveIntegerField(default=0)
    resource_id = models.UUIDField(null=True, db_index=True)
    cds_disable = models.BooleanField(default=False, blank=True)

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(
            resource_id__in=as207960_utils.models.get_object_ids(access_token, 'secondary-zone', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-secondary-zone"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, f"secondary-zone", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-secondary-zone"
        return as207960_utils.models.eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        self.zone_root = self.zone_root.lower()
        as207960_utils.models.sync_resource_to_keycloak(
            self,
            display_name="Secondary zone", scopes=[
                'view-secondary-zone',
                'edit-secondary-zone',
                'delete-secondary-zone',
            ],
            urn="urn:as207960:hexdns:secondary_zone", super_save=super().save, view_name='view_szone',
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        as207960_utils.models.delete_resource(self.resource_id)

    def get_user(self):
        return as207960_utils.models.get_resource_owner(self.resource_id)

    class Meta:
        verbose_name = "Secondary DNS Zone"
        verbose_name_plural = "Secondary DNS Zones"

    def __str__(self):
        return self.zone_root


class SecondaryDNSZoneRecord(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_szonerecord", primary_key=True)
    zone = models.ForeignKey(SecondaryDNSZone, on_delete=models.CASCADE)
    record_name = models.CharField(max_length=255)
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)")
    rtype = models.PositiveSmallIntegerField()
    rdata = models.BinaryField()

    class Meta:
        verbose_name = "Secondary DNS Zone Record"
        verbose_name_plural = "Secondary DNS Zones Record"
        ordering = ('record_name', 'rtype')
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def __str__(self):
        return f"{self.record_name} IN {self.rtype_name} {self.ttl}"

    @property
    def rtype_name(self):
        return dnslib.QTYPE.get(self.rtype)


class DNSZoneRecord(models.Model):
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE)
    record_name = models.CharField(
        max_length=255, default="@", verbose_name="Record name (@ for zone root)"
    )
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)", default=3600)

    def save(self, *args, **kwargs):
        self.record_name = self.record_name.lower()
        return super().save(*args, **kwargs)

    class Meta:
        abstract = True

    @property
    def dns_label(self):
        if self.record_name == "@":
            return dnslib.DNSLabel(self.zone.zone_root)
        else:
            return dnslib.DNSLabel(f"{self.record_name}.{self.zone.zone_root}")

    @classmethod
    def dns_label_to_record_name(cls, rname, zone):
        zone_name = dnslib.DNSLabel(zone.zone_root)
        if zone_name == rname:
            return "@"
        else:
            record_label = rname.stripSuffix(zone_name)
            return ".".join(map(lambda n: n.decode().lower(), record_label.label))

    def __str__(self):
        return self.record_name


class ReverseDNSZoneRecord(models.Model):
    zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE)
    record_address = models.GenericIPAddressField()
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)", default=3600)

    class Meta:
        abstract = True

    def clean(self):
        try:
            ipaddress.ip_address(self.record_address)
        except ValueError:
            return
        zone_network = ipaddress.ip_network(
            (self.zone.zone_root_address, self.zone.zone_root_prefix)
        )
        if ipaddress.ip_address(self.record_address) not in zone_network:
            raise ValidationError({"record_address": "Address not in zone network"})

    def __str__(self):
        return self.record_address


class AddressRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zoneaddressrecord", primary_key=True)
    address = models.GenericIPAddressField(verbose_name="Address (IPv4/IPv6)")
    auto_reverse = models.BooleanField(
        default=False, verbose_name="Automatically serve reverse PTR records"
    )

    class Meta:
        indexes = [models.Index(fields=['record_name', 'zone'])]

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            address=str(rr.rdata)
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.address = str(rr.rdata)

    def to_rr(self, query_name):
        address = ipaddress.ip_address(self.address)
        if type(address) == ipaddress.IPv4Address:
            return dnslib.RR(
                query_name,
                dnslib.QTYPE.A,
                rdata=dnslib.A(address.compressed),
                ttl=self.ttl,
            )
        elif type(address) == ipaddress.IPv6Address:
            return dnslib.RR(
                query_name,
                dnslib.QTYPE.AAAA,
                rdata=dnslib.AAAA(address.compressed),
                ttl=self.ttl,
            )


class DynamicAddressRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonedynamicaddressrecord", primary_key=True)
    current_ipv4 = models.GenericIPAddressField(protocol='ipv4', blank=True, null=True)
    current_ipv6 = models.GenericIPAddressField(protocol='ipv6', blank=True, null=True)
    password = models.CharField(max_length=255)

    class Meta:
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def to_rr_v4(self, query_name):
        if not self.current_ipv4:
            return None

        return dnslib.RR(
            query_name,
            dnslib.QTYPE.A,
            rdata=dnslib.A(self.current_ipv4),
            ttl=self.ttl,
        )

    def to_rr_v6(self, query_name):
        if not self.current_ipv6:
            return None

        return dnslib.RR(
            query_name,
            dnslib.QTYPE.AAAA,
            rdata=dnslib.AAAA(self.current_ipv6),
            ttl=self.ttl,
        )


class ANAMERecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zoneanamerecord", primary_key=True)
    alias = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.alias = self.alias.lower()
        return super().save(*args, **kwargs)

    def to_rrs(self, qtype, query_name):
        alias_label = dnslib.DNSLabel(self.alias)
        zone_label = dnslib.DNSLabel(self.zone.zone_root)

        out = []

        if alias_label.matchSuffix(zone_label):
            own_record_name = alias_label.stripSuffix(zone_label)
            search_name = ".".join(map(lambda n: n.decode(), own_record_name.label))
            own_records = self.zone.addressrecord_set.filter(record_name=search_name)
            for r in own_records:
                address = ipaddress.ip_address(r.address)
                if type(address) == ipaddress.IPv4Address and qtype == dnslib.QTYPE.A:
                    out.append(dnslib.RR(
                        query_name,
                        dnslib.QTYPE.A,
                        rdata=dnslib.A(address.compressed),
                        ttl=self.ttl,
                    ))
                elif type(address) == ipaddress.IPv6Address and qtype == dnslib.QTYPE.AAAA:
                    out.append(dnslib.RR(
                        query_name,
                        dnslib.QTYPE.AAAA,
                        rdata=dnslib.AAAA(address.compressed),
                        ttl=self.ttl,
                    ))
        else:
            question = dnslib.DNSRecord(q=dnslib.DNSQuestion(self.alias, qtype))
            try:
                res_pkt = question.send(
                    settings.RESOLVER_ADDR, port=settings.RESOLVER_PORT, ipv6=True, tcp=True, timeout=30
                )
            except socket.timeout:
                raise Exception(f"Failed to get address for {self.alias}: timeout")
            except struct.error:
                raise Exception(f"Failed to get address for {self.alias}: invalid response")
            res = dnslib.DNSRecord.parse(res_pkt)
            for rr in res.rr:
                out.append(dnslib.RR(
                    query_name,
                    qtype,
                    rdata=rr.rdata,
                    ttl=self.ttl
                ))

        return out

    def to_rrs_v4(self, query_name):
        return self.to_rrs(dnslib.QTYPE.A, query_name)

    def to_rrs_v6(self, query_name):
        return self.to_rrs(dnslib.QTYPE.AAAA, query_name)

    class Meta:
        verbose_name = "ANAME record"
        verbose_name_plural = "ANAME records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class CNAMERecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonecnamerecord", primary_key=True)
    alias = models.CharField(max_length=255)

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            alias=str(rr.rdata.label)
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.address = str(rr.rdata.label)

    def save(self, *args, **kwargs):
        self.alias = self.alias.lower()
        return super().save(*args, **kwargs)

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.CNAME,
            rdata=dnslib.CNAME(self.alias),
            ttl=self.ttl,
        )

    class Meta:
        verbose_name = "CNAME record"
        verbose_name_plural = "CNAME records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class MXRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonemxrecord", primary_key=True)
    exchange = models.CharField(max_length=255)
    priority = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            exchange=str(rr.rdata.label),
            priority=rr.rdata.preference
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.exchange = str(rr.rdata.label)
        self.priority = rr.rdata.preference

    def save(self, *args, **kwargs):
        self.exchange = self.exchange.lower()
        return super().save(*args, **kwargs)

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.MX,
            rdata=dnslib.MX(self.exchange, self.priority),
            ttl=self.ttl,
        )

    class Meta:
        verbose_name = "MX record"
        verbose_name_plural = "MX records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class NSRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonensrecord", primary_key=True)
    nameserver = models.CharField(max_length=255, verbose_name="Name server")

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            nameserver=str(rr.rdata.label)
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.nameserver = str(rr.rdata.label)

    def save(self, *args, **kwargs):
        self.nameserver = self.nameserver.lower()
        return super().save(*args, **kwargs)

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.NS,
            rdata=dnslib.NS(self.nameserver),
            ttl=self.ttl,
        )

    class Meta:
        verbose_name = "NS record"
        verbose_name_plural = "NS records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class TXTRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonetxtrecord", primary_key=True)
    data = models.TextField()

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            data="".join([x.decode(errors='replace') for x in rr.rdata.data])
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.data = "".join([x.decode(errors='replace') for x in rr.rdata.data])

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.TXT,
            rdata=dnslib.TXT(
                [
                    self.data[i: i + 255].encode()
                    for i in range(0, len(self.data), 255)
                ]
            ),
            ttl=self.ttl,
        )

    class Meta:
        verbose_name = "TXT record"
        verbose_name_plural = "TXT records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class SRVRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonesrvrecord", primary_key=True)
    priority = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    weight = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    port = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    target = models.CharField(max_length=255)

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            priority=rr.rdata.priority,
            weight=rr.rdata.weight,
            port=rr.rdata.port,
            target=str(rr.rdata.target)
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.priority = rr.rdata.priority
        self.weight = rr.rdata.weight
        self.port = rr.rdata.port
        self.target = str(rr.rdata.target)

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.SRV,
            rdata=dnslib.SRV(
                self.priority, self.weight, self.port, self.target
            ),
            ttl=self.ttl,
        )

    class Meta:
        verbose_name = "SRV record"
        verbose_name_plural = "SRV records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class CAARecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonecaarecord", primary_key=True)
    flag = models.PositiveIntegerField(validators=[MaxValueValidator(255)])
    tag = models.CharField(max_length=255)
    value = models.CharField(max_length=255)

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            flag=rr.rdata.flag,
            tag=rr.rdata.tag,
            value=rr.rdata.value
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.flag = rr.rdata.flag
        self.tag = rr.rdata.tag
        self.value = rr.rdata.value

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.CAA,
            rdata=dnslib.CAA(
                flags=self.flag, tag=self.tag, value=self.value
            ),
            ttl=self.ttl,
        )

    class Meta:
        verbose_name = "CAA record"
        verbose_name_plural = "CAA records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class NAPTRRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonenaptrrecord", primary_key=True)
    order = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    preference = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    flags = models.CharField(max_length=255)
    service = models.CharField(max_length=255)
    regexp = models.CharField(max_length=255)
    replacement = models.CharField(max_length=255)

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            order=rr.rdata.order,
            preference=rr.rdata.preference,
            flags=rr.rdata.flags,
            service=rr.rdata.service,
            regexp=rr.rdata.regexp,
            replacement=rr.rdata.replacement,
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.order = rr.rdata.order
        self.preference = rr.rdata.preference,
        self.flags = rr.rdata.flags,
        self.service = rr.rdata.service,
        self.regexp = rr.rdata.regexp,
        self.replacement = rr.rdata.replacement

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.NAPTR,
            rdata=dnslib.NAPTR(
                order=self.order,
                preference=self.preference,
                flags=self.flags,
                service=self.service,
                regexp=self.regexp,
                replacement=self.replacement,
            ),
            ttl=self.ttl,
        )

    class Meta:
        verbose_name = "NAPTR record"
        verbose_name_plural = "NAPTR records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class SSHFPRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonesshfprecord", primary_key=True)
    host_key = models.TextField(verbose_name="Host key (from /etc/ssh/ssh_host_ed25519_key.pub etc.)")

    @property
    def key(self):
        key = sshpubkeys.SSHKey(self.host_key, strict=False)
        key.parse()
        return key

    def clean(self):
        key = sshpubkeys.SSHKey(self.host_key, strict=False)
        try:
            key.parse()
        except sshpubkeys.InvalidKeyError as e:
            raise ValidationError({"host_key": f"Invalid key: {e}"})
        except NotImplementedError as e:
            raise ValidationError({"host_key": f"Invalid key type: {e}"})

    def to_rrs(self, query_name):
        out = []
        pubkey = self.key
        if pubkey.key_type == b"ssh-rsa":
            algo_num = 1
        elif pubkey.key_type == b"ssh-dsa":
            algo_num = 2
        elif pubkey.key_type.startswith(b"ecdsa-sha"):
            algo_num = 3
        elif pubkey.key_type == b"ssh-ed25519":
            algo_num = 4
        else:
            return []
        sha1_rd = bytearray(struct.pack("!BB", algo_num, 1))
        sha1_rd.extend(hashlib.sha1(pubkey._decoded_key).digest())
        sha256_rd = bytearray(struct.pack("!BB", algo_num, 2))
        sha256_rd.extend(hashlib.sha256(pubkey._decoded_key).digest())
        out.append(
            dnslib.RR(
                query_name, dnslib.QTYPE.SSHFP, rdata=dnslib.RD(sha1_rd), ttl=self.ttl,
            )
        )
        out.append(
            dnslib.RR(
                query_name, dnslib.QTYPE.SSHFP, rdata=dnslib.RD(sha256_rd), ttl=self.ttl,
            )
        )
        return out

    class Meta:
        verbose_name = "SSHFP record"
        verbose_name_plural = "SSHFP records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class DSRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonedsrecord", primary_key=True)
    ALGORITHMS = (
        (5, "RSA/SHA-1 (5) INSECURE"),
        (7, "RSASHA1-NSEC3-SHA1 (7) INSECURE"),
        (8, "RSA/SHA-256 (8)"),
        (10, "RSA/SHA-512 (10)"),
        (13, "ECDSA Curve P-256 with SHA-256 (13)"),
        (14, "ECDSA Curve P-384 with SHA-384 (14)"),
        (15, "Ed25519 (15)"),
        (16, "Ed448 (16)"),
    )

    DIGEST_TYPES = (
        (1, "SHA-1 (1) INSECURE"),
        (2, "SHA-256 (2)"),
        (3, "GOST R 34.11-94 (3)"),
        (4, "SHA-384 (4)"),
    )

    key_tag = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    algorithm = models.PositiveSmallIntegerField(choices=ALGORITHMS)
    digest_type = models.PositiveSmallIntegerField(choices=DIGEST_TYPES)
    digest = models.TextField()

    @property
    def digest_bin(self):
        try:
            return bytearray.fromhex(self.digest)
        except ValueError:
            try:
                return base64.b64decode(self.digest)
            except binascii.Error:
                return None

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        tags_len = struct.calcsize("!HBB")
        key_tag, algorithm, digest_type = struct.pack("!HBB", rr.rdata.data)
        digest = rr.rdata.data[tags_len:]
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            key_tag=key_tag,
            algorithm=algorithm,
            digest_type=digest_type,
            digest=codecs.encode(digest, "hex").decode()
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        tags_len = struct.calcsize("!HBB")
        key_tag, algorithm, digest_type = struct.pack("!HBB", rr.rdata.data)
        digest = rr.rdata.data[tags_len:]
        self.record_name = record_name
        self.ttl = rr.ttl
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = codecs.encode(digest, "hex").decode()

    def to_rr(self, query_name):
        ds_data = bytearray(
            struct.pack(
                "!HBB", self.key_tag, self.algorithm, self.digest_type
            )
        )
        digest_data = self.digest_bin
        if not digest_data:
            return None
        ds_data.extend(digest_data)
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.DS,
            rdata=dnslib.RD(ds_data),
            ttl=self.ttl,
        )

    class Meta:
        verbose_name = "DS record"
        verbose_name_plural = "DS records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class LOCRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonelocrecord", primary_key=True)
    latitude = models.FloatField(
        validators=[MaxValueValidator(90), MinValueValidator(-90)], verbose_name="Latitude (deg)"
    )
    longitude = models.FloatField(
        validators=[MaxValueValidator(180), MinValueValidator(-180)], verbose_name="Longitude (deg)"
    )
    altitude = models.FloatField(validators=[
        MinValueValidator(-100000.00), MaxValueValidator(42849672.95)
    ], verbose_name="Altitude (m)", default=0)
    size = models.FloatField(validators=[
        MinValueValidator(0), MaxValueValidator(90000000.00)
    ], verbose_name="Size (m)", default=0)
    hp = models.FloatField(validators=[
        MinValueValidator(0), MaxValueValidator(90000000.00)
    ], verbose_name="Horizontal precision (m)", default=0)
    vp = models.FloatField(validators=[
        MinValueValidator(0), MaxValueValidator(90000000.00)
    ], verbose_name="Vertical precision (m)", default=0)

    @staticmethod
    def _dec_size(value):
        size_exp = value & 0x0F
        size_man = (value & 0xF0) >> 4

        return size_man * (10 ** size_exp)

    @classmethod
    def _dec_rdata(cls, rdata):
        _, size, hp, vp, lat, long, alt = struct.unpack("!BBBBIII", rdata)

        size = cls._dec_size(size)
        hp = cls._dec_size(hp)
        vp = cls._dec_size(vp)

        lat = ((lat - 2 ** 31) / 3600.0 / 1000.0)
        long = ((long - 2 ** 31) / 3600.0 / 1000.0)
        alt = ((alt / 100.0) - 100000)

        return size, hp, vp, lat, long, alt

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        size, hp, vp, lat, long, alt = cls._dec_size(rr.rdata.data)

        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            latitude=lat,
            longitude=long,
            altitude=alt,
            size=size,
            hp=hp,
            vp=vp
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        size, hp, vp, lat, long, alt = self._dec_size(rr.rdata.data)

        self.record_name = record_name
        self.ttl = rr.ttl
        self.latitude = lat
        self.longitude = long
        self.altitude = alt
        self.size = size
        self.hp = hp
        self.vp = vp

    def to_rr(self, query_name):
        def enc_size(value):
            size_exp = int(math.floor(math.log10(value)) if value != 0 else 0)
            size_man = int(value / (10 ** size_exp))

            return ((size_man << 4) & 0xF0) + (size_exp & 0x0F)

        lat = int(self.latitude * 3600 * 1000) + 2 ** 31
        long = int(self.longitude * 3600 * 1000) + 2 ** 31
        alt = int((self.altitude + 100000) * 100)

        loc_data = bytearray(struct.pack(
            "!BBBBIII", 0, enc_size(self.size * 100), enc_size(self.hp * 100), enc_size(self.vp * 100),
            lat, long, alt
        ))
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.LOC,
            rdata=dnslib.RD(loc_data),
            ttl=self.ttl
        )

    class Meta:
        verbose_name = "LOC record"
        verbose_name_plural = "LOC records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class HINFORecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonehinforecord", primary_key=True)
    cpu = models.CharField(max_length=255, verbose_name="CPU")
    os = models.CharField(max_length=255, verbose_name="OS")

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        rdata_buffer = dnslib.DNSBuffer(rr.rdata.data)
        rdata = dnslib.TXT.parse(rdata_buffer, len(rr.rdata.data))
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            cpu=rdata.data[0].decode(errors='replace'),
            os=rdata.data[1].decode(errors='replace'),
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        rdata_buffer = dnslib.DNSBuffer(rr.rdata.data)
        rdata = dnslib.TXT.parse(rdata_buffer, len(rr.rdata.data))
        self.record_name = record_name
        self.ttl = rr.ttl
        self.cpu = rdata.data[0].decode(errors='replace')
        self.os = rdata.data[1].decode(errors='replace')

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.HINFO,
            rdata=dnslib.TXT([self.cpu, self.os]),
            ttl=self.ttl
        )

    class Meta:
        verbose_name = "HINFO record"
        verbose_name_plural = "HINFO records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class RPRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonerprecord", primary_key=True)
    mailbox = models.CharField(max_length=255)
    txt = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.mailbox = self.mailbox.lower()
        self.txt = self.txt.lower()
        return super().save(*args, **kwargs)

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        rdata_buffer = dnslib.DNSBuffer(rr.rdata.data)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            mailbox=str(rdata_buffer.decode_name()),
            txt=str(rdata_buffer.decode_name()),
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        rdata_buffer = dnslib.DNSBuffer(rr.rdata.data)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.mailbox = str(rdata_buffer.decode_name())
        self.txt = str(rdata_buffer.decode_name())

    def to_rr(self, query_name):
        buffer = dnslib.DNSBuffer()
        buffer.encode_name(dnslib.DNSLabel(self.mailbox))
        buffer.encode_name(dnslib.DNSLabel(self.txt))
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.RP,
            rdata=dnslib.RD(buffer.data),
            ttl=self.ttl
        )

    class Meta:
        verbose_name = "RP record"
        verbose_name_plural = "RP records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class PTRRecord(ReverseDNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_rzoneptrrecord", primary_key=True)
    pointer = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.pointer = self.pointer.lower()
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = "PTR record"
        verbose_name_plural = "PTR records"
        indexes = [models.Index(fields=['record_address', 'zone'])]


class ReverseNSRecord(ReverseDNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_rzonensrecord", primary_key=True)
    record_prefix = models.PositiveIntegerField(validators=[MaxValueValidator(128)])
    nameserver = models.CharField(max_length=255, verbose_name="Name server")

    @property
    def network(self):
        try:
            return ipaddress.ip_network(
                (self.record_address, self.record_prefix)
            )
        except ValueError:
            return None

    def save(self, *args, **kwargs):
        self.nameserver = self.nameserver.lower()
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = "NS record"
        verbose_name_plural = "NS records"
        indexes = [models.Index(fields=['record_address', 'zone'])]
