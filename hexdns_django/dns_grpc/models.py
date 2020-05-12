from django.db import models
from django.conf import settings
import uuid
import ipaddress
import sshpubkeys
import base64
import binascii
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator


class DNSZone(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    zone_root = models.CharField(max_length=255)
    last_modified = models.DateTimeField()
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True
    )
    zsk_private = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "DNS Zone"
        verbose_name_plural = "DNS Zones"

    def __str__(self):
        return self.zone_root


class ReverseDNSZone(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    zone_root_address = models.GenericIPAddressField()
    zone_root_prefix = models.PositiveIntegerField(validators=[MaxValueValidator(128)])
    last_modified = models.DateTimeField()
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True
    )
    zsk_private = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = "Reverse DNS Zone"
        verbose_name_plural = "Reverse DNS Zones"

    def clean(self):
        try:
            ipaddress.ip_network((self.zone_root_address, self.zone_root_prefix))
        except ValueError as e:
            raise ValidationError(str(e))

    def __str__(self):
        return f"{self.zone_root_address}/{self.zone_root_prefix}"


class DNSZoneRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE)
    record_name = models.CharField(
        max_length=255, default="@", verbose_name="Record name (@ for zone root)"
    )
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)")

    class Meta:
        abstract = True

    def __str__(self):
        return self.record_name


class ReverseDNSZoneRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE)
    record_address = models.GenericIPAddressField()
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)")

    class Meta:
        abstract = True

    def clean(self):
        zone_network = ipaddress.ip_network(
            (self.zone.zone_root_address, self.zone.zone_root_prefix)
        )
        if ipaddress.ip_address(self.record_address) not in zone_network:
            raise ValidationError({"record_address": "Address not in zone network"})

    def __str__(self):
        return self.record_address


class AddressRecord(DNSZoneRecord):
    address = models.GenericIPAddressField(verbose_name="Address (IPv4/IPv6)")
    auto_reverse = models.BooleanField(
        default=False, verbose_name="Automatically serve reverse PTR records"
    )


class DynamicAddressRecord(DNSZoneRecord):
    current_ipv4 = models.GenericIPAddressField(protocol='ipv4', blank=True, null=True)
    current_ipv6 = models.GenericIPAddressField(protocol='ipv6', blank=True, null=True)
    password = models.CharField(max_length=255)


class CNAMERecord(DNSZoneRecord):
    alias = models.CharField(max_length=255)

    class Meta:
        verbose_name = "CNAME record"
        verbose_name_plural = "CNAME records"


class MXRecord(DNSZoneRecord):
    exchange = models.CharField(max_length=255)
    priority = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])

    class Meta:
        verbose_name = "MX record"
        verbose_name_plural = "MX records"


class NSRecord(DNSZoneRecord):
    nameserver = models.CharField(max_length=255, verbose_name="Name server")

    class Meta:
        verbose_name = "NS record"
        verbose_name_plural = "NS records"


class TXTRecord(DNSZoneRecord):
    data = models.TextField()

    class Meta:
        verbose_name = "TXT record"
        verbose_name_plural = "TXT records"


class SRVRecord(DNSZoneRecord):
    priority = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    weight = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    port = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    target = models.CharField(max_length=255)

    class Meta:
        verbose_name = "SRV record"
        verbose_name_plural = "SRV records"


class CAARecord(DNSZoneRecord):
    flag = models.PositiveIntegerField(validators=[MaxValueValidator(255)])
    tag = models.CharField(max_length=255)
    value = models.CharField(max_length=255)

    class Meta:
        verbose_name = "CAA record"
        verbose_name_plural = "CAA records"


class NAPTRRecord(DNSZoneRecord):
    order = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    preference = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    flags = models.CharField(max_length=255)
    service = models.CharField(max_length=255)
    regexp = models.CharField(max_length=255)
    replacement = models.CharField(max_length=255)

    class Meta:
        verbose_name = "NAPTR record"
        verbose_name_plural = "NAPTR records"


class SSHFPRecord(DNSZoneRecord):
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

    class Meta:
        verbose_name = "SSHFP record"
        verbose_name_plural = "SSHFP records"


class DSRecord(DNSZoneRecord):
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

    class Meta:
        verbose_name = "DS record"
        verbose_name_plural = "DS records"


class PTRRecord(ReverseDNSZoneRecord):
    pointer = models.CharField(max_length=255)

    class Meta:
        verbose_name = "PTR record"
        verbose_name_plural = "PTR records"
