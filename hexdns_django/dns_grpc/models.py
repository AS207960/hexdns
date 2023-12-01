import base64
import binascii
import ipaddress
import struct
import math
import secrets
import hashlib
import idna
import django_keycloak_auth.clients
import dnslib
import codecs
import sshpubkeys
import uuid
import kubernetes
import string
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models, transaction
from django.db.models.signals import post_save
from django.dispatch import receiver
import as207960_utils.models
from . import svcb, tasks

if settings.KUBE_IN_CLUSTER:
    kubernetes.config.load_incluster_config()
else:
    kubernetes.config.load_kube_config()

DNS_ALPHABET = string.ascii_lowercase + string.digits + "-."


class DNSError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)


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
    last_resign = models.DateTimeField(null=True, blank=True)
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

    def setup_initial_records(self):
        self.create_blank_spf()
        self.create_blank_dmarc()
        TXTRecord(
            zone=self,
            record_name="*._domainkey",
            ttl=86400,
            data="v=DKIM1; p=",
        ).save()

    def create_blank_spf(self):
        TXTRecord(
            zone=self,
            record_name="@",
            ttl=86400,
            data="v=spf1 -all",
        ).save()

    def create_blank_dmarc(self):
        TXTRecord(
            zone=self,
            record_name="_dmarc",
            ttl=86400,
            data="v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s",
        ).save()

    def import_zone_file(self, zone_data, overwrite=False):
        suffix = dnslib.DNSLabel(self.zone_root)
        p = dnslib.ZoneParser(zone_data, origin=suffix)
        try:
            records = list(p)
        except (dnslib.DNSError, ValueError, IndexError) as e:
            raise ValueError(f"Invalid zone file: {str(e)}")
        else:
            with transaction.atomic():
                if overwrite:
                    self.addressrecord_set.all().delete()
                    self.cnamerecord_set.all().delete()
                    self.mxrecord_set.all().delete()
                    self.nsrecord_set.all().delete()
                    self.txtrecord_set.all().delete()
                    self.srvrecord_set.all().delete()
                    self.caarecord_set.all().delete()
                    self.naptrrecord_set.all().delete()
                    self.dnskeyrecord_set.all().delete()

                for record in records:
                    if record.rclass != dnslib.CLASS.IN:
                        continue
                    if record.rtype == dnslib.QTYPE.A:
                        r = AddressRecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.AAAA:
                        r = AddressRecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.CNAME:
                        r = CNAMERecord.from_rr(record, self)
                        self.cnamerecord_set.filter(record_name=r.record_name).delete()
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.MX:
                        r = MXRecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.NS:
                        r = NSRecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.TXT:
                        r = TXTRecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.SRV:
                        r = SRVRecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.CAA:
                        r = CAARecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.NAPTR:
                        r = NAPTRRecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()
                    elif record.rtype == dnslib.QTYPE.DNSKEY:
                        r = DNSKEYRecord.from_rr(record, self)
                        if r.ttl <= 1:
                            r.ttl = 3600
                        r.save()


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

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.dns_zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.dns_zone.id)
        return super().delete(*args, **kwargs)


class DNSZoneAdditionalCDNSKEY(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_zoneadditionalcdnskey", primary_key=True)
    dns_zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE, related_name='additional_cdnskey')
    flags = models.SmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(65535)])
    protocol = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    algorithm = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    public_key = models.TextField(validators=[b64_validator])

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.dns_zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.dns_zone.id)
        return super().delete(*args, **kwargs)


class DNSZoneCustomNS(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_zonecustomns", primary_key=True)
    dns_zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE, related_name='custom_ns')
    nameserver = models.CharField(max_length=255, verbose_name="Name server")

    def save(self, *args, **kwargs):
        self.nameserver = self.nameserver.lower()
        tasks.update_fzone.delay(self.dns_zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.dns_zone.id)
        return super().delete(*args, **kwargs)


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
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=1, choices=TYPES)
    restrict_to = models.CharField(
        max_length=255, default="@", verbose_name="Restrict to (@ for zone root)"
    )
    secret = models.BinaryField(default=make_update_secret)
    last_used = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.id}.{self.zone.zone_root})"

    @property
    def secret_str(self):
        return base64.b64encode(self.secret).decode()


class DNSZoneAXFRSecrets(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_zoneaxfrsecret", primary_key=True)
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    secret = models.BinaryField(default=make_update_secret)
    last_used = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.id}.{self.zone.zone_root})"

    @property
    def secret_str(self):
        return base64.b64encode(self.secret).decode()


class DNSZoneAXFRIPACL(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_zoneaxfripacl", primary_key=True)
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    address = models.GenericIPAddressField(db_index=True)
    prefix = models.PositiveIntegerField(validators=[MaxValueValidator(128)], db_index=True)
    last_used = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.address}/{self.prefix})"

    def clean(self):
        try:
            ipaddress.ip_network((self.address, self.prefix))
        except ValueError as e:
            raise ValidationError(str(e))

    @property
    def network(self):
        try:
            return ipaddress.ip_network(
                (self.address, self.prefix)
            )
        except ValueError:
            return None


class DNSZoneAXFRNotify(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_zoneaxfrnotify", primary_key=True)
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    server = models.CharField(max_length=255)
    port = models.PositiveSmallIntegerField(default=53, validators=[MaxValueValidator(65535)])

    def __str__(self):
        return f"{self.name} ({self.server}:{self.port})"


class ReverseDNSZone(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzone", primary_key=True)
    zone_root_address = models.GenericIPAddressField(db_index=True)
    zone_root_prefix = models.PositiveIntegerField(validators=[MaxValueValidator(128)], db_index=True)
    last_modified = models.DateTimeField()
    zsk_private = models.TextField(blank=True, null=True)
    last_resign = models.DateTimeField(null=True, blank=True)
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

    def save(self, *args, **kwargs):
        tasks.update_rzone.delay(self.dns_zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_rzone.delay(self.dns_zone.id)
        return super().delete(*args, **kwargs)


class ReverseDNSZoneAdditionalCDNSKEY(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzoneadditionalcdnskey", primary_key=True)
    dns_zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE, related_name='additional_cdnskey')
    flags = models.SmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(65535)])
    protocol = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    algorithm = models.SmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)])
    public_key = models.TextField(validators=[b64_validator])

    def save(self, *args, **kwargs):
        tasks.update_rzone.delay(self.dns_zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_rzone.delay(self.dns_zone.id)
        return super().delete(*args, **kwargs)


class ReverseDNSZoneAXFRSecrets(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzoneaxfrsecret", primary_key=True)
    zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    secret = models.BinaryField(default=make_update_secret)
    last_used = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.id}.{self.zone.zone_root})"

    @property
    def secret_str(self):
        return base64.b64encode(self.secret).decode()


class ReverseDNSZoneAXFRIPACL(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzoneaxfripacl", primary_key=True)
    zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    address = models.GenericIPAddressField(db_index=True)
    prefix = models.PositiveIntegerField(validators=[MaxValueValidator(128)], db_index=True)
    last_used = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.address}/{self.prefix})"

    def clean(self):
        try:
            ipaddress.ip_network((self.address, self.prefix))
        except ValueError as e:
            raise ValidationError(str(e))

    @property
    def network(self):
        try:
            return ipaddress.ip_network(
                (self.address, self.prefix)
            )
        except ValueError:
            return None


class ReverseDNSZoneAXFRNotify(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzoneaxfrnotify", primary_key=True)
    zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    server = models.CharField(max_length=255)
    port = models.PositiveSmallIntegerField(default=53, validators=[MaxValueValidator(65535)])

    def __str__(self):
        return f"{self.name} ({self.server}:{self.port})"


class ReverseDNSZoneCustomNS(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_rzonecustomns", primary_key=True)
    dns_zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE, related_name='custom_ns')
    nameserver = models.CharField(max_length=255, verbose_name="Name server")

    def save(self, *args, **kwargs):
        self.nameserver = self.nameserver.lower()
        tasks.update_rzone.delay(self.dns_zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_rzone.delay(self.dns_zone.id)
        return super().delete(*args, **kwargs)


class SecondaryDNSZone(models.Model):
    id = as207960_utils.models.TypedUUIDField("hexdns_szone", primary_key=True)
    zone_root = models.CharField(max_length=255, db_index=True)
    serial = models.PositiveIntegerField(null=True)
    primary = models.CharField(max_length=255)
    charged = models.BooleanField(default=True, blank=True)
    active = models.BooleanField(default=False, blank=True)
    error = models.BooleanField(default=False, blank=True)
    error_message = models.CharField(max_length=255, blank=True, null=True)
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
    zone = models.ForeignKey(SecondaryDNSZone, on_delete=models.CASCADE, db_index=True)
    record_text = models.TextField()

    class Meta:
        verbose_name = "Secondary DNS Zone Record"
        verbose_name_plural = "Secondary DNS Zones Record"

    def __str__(self):
        return self.record_text


class DNSZoneRecord(models.Model):
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE, db_index=True)
    record_name = models.CharField(
        max_length=255, default="@", verbose_name="Record name (@ for zone root)",
        db_index=True
    )
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)", default=3600)

    def save(self, *args, **kwargs):
        self.record_name = self.record_name.lower()
        return super().save(*args, **kwargs)

    class Meta:
        abstract = True
        ordering = ['record_name']

    @property
    def dns_label(self):
        if self.record_name == "@":
            return dnslib.DNSLabel(self.zone.zone_root)
        else:
            return dnslib.DNSLabel(f"{self.idna_label}.{self.zone.zone_root}")

    @property
    def record_label(self):
        return self.idna_label

    @property
    def idna_label(self):
        if self.record_name.strip() == "@" or self.record_name.strip() == '':
            return "@"
        try:
            return idna.encode(self.record_name, uts46=True).decode()
        except idna.IDNAError:
            allowed_chars = string.ascii_letters + string.digits + "-_ *."
            if all(c in allowed_chars for c in self.record_name):
                return self.record_name.replace(" ", "\\040")

            return None

    @classmethod
    def dns_label_to_record_name(cls, rname, zone):
        zone_name = dnslib.DNSLabel(zone.zone_root)
        if zone_name == rname:
            return "@"
        else:
            record_label = rname.stripSuffix(zone_name)
            return ".".join(map(lambda n: n.decode().lower(), record_label.label))

    def validate_unique(self, exclude=None):
        if "record_name" not in exclude:
            other_cnames = len(
                self.zone.cnamerecord_set
                .filter(record_name=self.record_label)
            )
            if other_cnames >= 1:
                raise ValidationError({
                    "record_name": "A CNAME already exists with the same label"
                })

        super().validate_unique(exclude=exclude)

    def __str__(self):
        return self.record_name


class ReverseDNSZoneRecord(models.Model):
    zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE, db_index=True)
    record_address = models.GenericIPAddressField(db_index=True)
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)", default=3600)

    class Meta:
        abstract = True
        ordering = ['record_address']

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
        default=True, verbose_name="Automatically serve reverse PTR records"
    )

    class Meta(DNSZoneRecord.Meta):
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

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


class DynamicAddressRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonedynamicaddressrecord", primary_key=True)
    current_ipv4 = models.GenericIPAddressField(protocol='ipv4', blank=True, null=True)
    current_ipv6 = models.GenericIPAddressField(protocol='ipv6', blank=True, null=True)
    password = models.CharField(max_length=255)

    class Meta(DNSZoneRecord.Meta):
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

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


class ANAMERecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zoneanamerecord", primary_key=True)
    alias = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.alias = self.alias.lower()
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

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
            for r in self.cached.all():
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

        return out

    def to_rrs_v4(self, query_name):
        return self.to_rrs(dnslib.QTYPE.A, query_name)

    def to_rrs_v6(self, query_name):
        return self.to_rrs(dnslib.QTYPE.AAAA, query_name)

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "ANAME record"
        verbose_name_plural = "ANAME records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class ANAMERecordCache(models.Model):
    record = models.ForeignKey(ANAMERecord, on_delete=models.CASCADE, related_name='cached')
    address = models.GenericIPAddressField(verbose_name="Address (IPv4/IPv6)")

    def __str__(self):
        return f"{self.record.alias} -> {self.address}"


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
        self.alias = str(rr.rdata.label)

    def clean_fields(self, exclude=None):
        if self.record_name == "@" and "record_name" not in exclude:
            raise ValidationError({
                "record_name": "CNAME records cannot exit at the zone root"
            })

        super().clean_fields(exclude=exclude)

    def save(self, *args, **kwargs):
        self.alias = self.alias.lower()
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.CNAME,
            rdata=dnslib.CNAME(self.alias),
            ttl=self.ttl,
        )

    def validate_unique(self, exclude=None):
        if "record_name" not in exclude:
            other_records = 0
            other_records += len(
                self.zone.cnamerecord_set
                .filter(record_name=self.record_label)
                .exclude(id=self.id)
            )

            record_types = [
                self.zone.addressrecord_set, self.zone.dynamicaddressrecord_set, self.zone.anamerecord_set,
                self.zone.githubpagesrecord_set, self.zone.redirectrecord_set, self.zone.mxrecord_set,
                self.zone.nsrecord_set, self.zone.txtrecord_set, self.zone.srvrecord_set, self.zone.caarecord_set,
                self.zone.naptrrecord_set, self.zone.sshfprecord_set, self.zone.dsrecord_set, self.zone.locrecord_set,
                self.zone.hinforecord_set, self.zone.rprecord_set, self.zone.dhcidrecord_set,
            ]
            for t in record_types:
                other_records += len(t.filter(record_name=self.record_label))

            for r in self.zone.httpsrecord_set.all():
                if r.record_label == self.record_label:
                    other_records += 1
                    break

            if other_records >= 1:
                raise ValidationError({
                    "record_name": "Another record already exists with the same label"
                })

        if exclude is None:
            exclude = set()
        exclude.add("record_name")
        super().validate_unique(exclude=exclude)

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "CNAME record"
        verbose_name_plural = "CNAME records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class RedirectRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zoneredirectrecord", primary_key=True)
    target = models.URLField()
    include_path = models.BooleanField(blank=True)

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        api_client = kubernetes.client.NetworkingV1Api()
        dns_name = ".".join(l.decode() for l in self.dns_label.label)
        ingress_name = str(self.id).replace("_", "-")

        spec = kubernetes.client.models.V1IngressSpec(
            rules=[kubernetes.client.models.V1IngressRule(
                host=dns_name,
                http=kubernetes.client.models.V1HTTPIngressRuleValue(
                    paths=[kubernetes.client.models.V1HTTPIngressPath(
                        path_type="Prefix",
                        path="/",
                        backend=kubernetes.client.models.V1IngressBackend(
                            service=kubernetes.client.models.V1IngressServiceBackend(
                                name="hexdns-redirect",
                                port=kubernetes.client.models.V1ServiceBackendPort(
                                    number=8000
                                )
                            )
                        )
                    )]
                )
            )],
            tls=[kubernetes.client.models.V1IngressTLS(
                hosts=[dns_name],
                secret_name=f"{ingress_name}-tls"
            )]
        )

        try:
            api_client.read_namespaced_ingress(ingress_name, settings.KUBE_NAMESPACE)
            api_client.patch_namespaced_ingress(
                ingress_name, settings.KUBE_NAMESPACE, kubernetes.client.models.V1Ingress(spec=spec)
            )
        except kubernetes.client.ApiException as e:
            if e.status == 404:
                api_client.create_namespaced_ingress(
                    settings.KUBE_NAMESPACE, kubernetes.client.models.V1Ingress(
                        metadata=kubernetes.client.models.V1ObjectMeta(
                            name=ingress_name,
                            annotations={
                                "cert-manager.io/cluster-issuer": "letsencrypt"
                            }
                        ),
                        spec=spec
                    )
                )
            else:
                raise e

        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        api_client = kubernetes.client.NetworkingV1Api()
        ingress_name = str(self.id).replace("_", "-")
        api_client.delete_namespaced_ingress(ingress_name, settings.KUBE_NAMESPACE)
        return super().delete(*args, **kwargs)

    def to_rr_v4(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.A,
            rdata=dnslib.A("45.129.95.254"),
            ttl=self.ttl,
        )

    def to_rr_v6(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.AAAA,
            rdata=dnslib.AAAA("2a0e:1cc1:1::1:7"),
            ttl=self.ttl,
        )

    def to_rr_caa(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.CAA,
            rdata=dnslib.CAA(
                flags=0, tag="issue", value="letsencrypt.org"
            ),
            ttl=self.ttl,
        )

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "Redirect record"
        verbose_name_plural = "Redirect records"
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
        tasks.update_fzone.delay(self.zone.id)
        self.exchange = self.exchange.lower()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.MX,
            rdata=dnslib.MX(self.exchange, self.priority),
            ttl=self.ttl,
        )

    class Meta(DNSZoneRecord.Meta):
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
        tasks.update_fzone.delay(self.zone.id)
        self.nameserver = self.nameserver.lower()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.NS,
            rdata=dnslib.NS(self.nameserver),
            ttl=self.ttl,
        )

    class Meta(DNSZoneRecord.Meta):
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

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "TXT record"
        verbose_name_plural = "TXT records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


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

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "SRV record"
        verbose_name_plural = "SRV records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


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
            flag=rr.rdata.flags,
            tag=rr.rdata.tag,
            value=rr.rdata.value
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.flag = rr.rdata.flags
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

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "CAA record"
        verbose_name_plural = "CAA records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


class NAPTRRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonenaptrrecord", primary_key=True)
    order = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    preference = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    flags = models.CharField(max_length=255)
    service = models.CharField(max_length=255)
    regexp = models.CharField(max_length=255, blank=True, null=True)
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

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "NAPTR record"
        verbose_name_plural = "NAPTR records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


class SSHFP(dnslib.RD):
    attrs = ('algorithm', 'fingerprint_type', 'fingerprint')

    def __init__(self, algorithm, fingerprint_type, fingerprint):
        self.algorithm = algorithm
        self.fingerprint_type = fingerprint_type
        self.fingerprint = fingerprint

    def pack(self, buffer):
        buffer.pack("!BB", self.algorithm, self.fingerprint_type)
        buffer.append(self.fingerprint)

    def __repr__(self):
        return f"{self.algorithm} {self.fingerprint_type} {binascii.hexlify(self.fingerprint).decode()}"


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
        out.append(
            dnslib.RR(
                query_name, dnslib.QTYPE.SSHFP, rdata=SSHFP(
                    algo_num,
                    1,
                    hashlib.sha1(pubkey._decoded_key).digest()
                ), ttl=self.ttl,
            )
        )
        out.append(
            dnslib.RR(
                query_name, dnslib.QTYPE.SSHFP, rdata=SSHFP(
                    algo_num,
                    2,
                    hashlib.sha256(pubkey._decoded_key).digest()
                ), ttl=self.ttl,
            )
        )
        return out

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "SSHFP record"
        verbose_name_plural = "SSHFP records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


class DS(dnslib.RD):
    attrs = ('key_tag', 'algorithm', 'digest_type', 'digest')

    def __init__(self, key_tag, algorithm, digest_type, digest):
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = digest

    def pack(self, buffer):
        buffer.pack("!HBB", self.key_tag, self.algorithm, self.digest_type)
        buffer.append(self.digest)

    def __repr__(self):
        return f"{self.key_tag} {self.algorithm} {self.digest_type} {binascii.hexlify(self.digest).decode()}"


DNSSEC_ALGORITHMS = (
    (5, "RSA/SHA-1 (5) INSECURE"),
    (7, "RSASHA1-NSEC3-SHA1 (7) INSECURE"),
    (8, "RSA/SHA-256 (8)"),
    (10, "RSA/SHA-512 (10)"),
    (13, "ECDSA Curve P-256 with SHA-256 (13)"),
    (14, "ECDSA Curve P-384 with SHA-384 (14)"),
    (15, "Ed25519 (15)"),
    (16, "Ed448 (16)"),
)

class DSRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonedsrecord", primary_key=True)

    DIGEST_TYPES = (
        (1, "SHA-1 (1) INSECURE"),
        (2, "SHA-256 (2)"),
        (3, "GOST R 34.11-94 (3)"),
        (4, "SHA-384 (4)"),
    )

    key_tag = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])
    algorithm = models.PositiveSmallIntegerField(choices=DNSSEC_ALGORITHMS)
    digest_type = models.PositiveSmallIntegerField(choices=DIGEST_TYPES)
    digest = models.TextField(validators=[hex_validator])

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
        key_tag, algorithm, digest_type = struct.unpack("!HBB", rr.rdata.data)
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
        key_tag, algorithm, digest_type = struct.unpack("!HBB", rr.rdata.data)
        digest = rr.rdata.data[tags_len:]
        self.record_name = record_name
        self.ttl = rr.ttl
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = codecs.encode(digest, "hex").decode()

    def to_rr(self, query_name):
        digest_data = self.digest_bin
        if not digest_data:
            return None
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.DS,
            rdata=DS(self.key_tag, self.algorithm, self.digest_type, digest_data),
            ttl=self.ttl,
        )

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "DS record"
        verbose_name_plural = "DS records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

    def clean_fields(self, exclude=None):
        if self.record_name == "@" and "record_name" not in exclude:
            raise ValidationError({
                "record_name": "DS records cannot exit at the zone root"
            })

        super().clean_fields(exclude=exclude)


class DNSKEYRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonednskeyrecord", primary_key=True)

    DIGEST_TYPES = (
        (1, "SHA-1 (1) INSECURE"),
        (2, "SHA-256 (2)"),
        (3, "GOST R 34.11-94 (3)"),
        (4, "SHA-384 (4)"),
    )

    flags = models.PositiveSmallIntegerField(validators=[MinValueValidator(0), MaxValueValidator(65535)])
    protocol = models.PositiveSmallIntegerField(validators=[MinValueValidator(1), MaxValueValidator(255)], default=3)
    algorithm = models.PositiveSmallIntegerField(choices=DNSSEC_ALGORITHMS)
    public_key = models.TextField(validators=[b64_validator])

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            flags=rr.rdata.flags,
            protocol=rr.rdata.protocol,
            algorithm=rr.rdata.algorithm,
            public_key=base64.b64encode(rr.rdata.key)
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.flags = rr.rdata.flags
        self.protocol = rr.rdata.protocol
        self.algorithm = rr.rdata.algorithm
        self.public_key = base64.b64encode(rr.rdata.key)

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.DS,
            rdata=dnslib.DNSKEY(
                algorithm=self.algorithm,
                flags=self.flags,
                protocol=self.protocol,
                key=base64.b64decode(self.public_key)
            ),
            ttl=self.ttl,
        )

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "DNSKEY record"
        verbose_name_plural = "DNSKEY records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


class LOC(dnslib.RD):
    attrs = ('lat', 'long', 'altitude', 'size', 'hp', 'vp')

    def __init__(self, lat, long, altitude, size, hp, vp):
        self.lat = lat
        self.long = long
        self.altitude = altitude
        self.size = size
        self.hp = hp
        self.vp = vp
        super().__init__()

    def pack(self, buffer):
        def enc_size(value):
            size_exp = int(math.floor(math.log10(value)) if value != 0 else 0)
            size_man = int(value / (10 ** size_exp))

            return ((size_man << 4) & 0xF0) + (size_exp & 0x0F)

        lat = int(self.lat * 3600 * 1000) + 2 ** 31
        long = int(self.long * 3600 * 1000) + 2 ** 31
        alt = int((self.altitude + 100000) * 100)

        buffer.pack(
            "!BBBBIII", 0, enc_size(self.size * 100), enc_size(self.hp * 100), enc_size(self.vp * 100),
            lat, long, alt
        )

    def __repr__(self):
        lat_abs = abs(self.lat)
        lat_d = int(lat_abs)
        lat_m = int((lat_abs - lat_d) * 60)
        lat_s = round((lat_abs - lat_d - lat_m / 60) * 3600)
        long_abs = abs(self.long)
        long_d = int(long_abs)
        long_m = int((long_abs - long_d) * 60)
        long_s = round((long_abs - long_d - long_m / 60) * 3600)

        return f"{lat_d} {lat_m} {lat_s} {'N' if self.lat >= 0 else 'S'} " \
               f"{long_d} {long_m} {long_s} {'E' if self.long >= 0 else 'W'} " \
               f"{self.altitude:.2f}m {self.size:.2f}m {self.hp:.2f}m {self.vp:.2f}m"


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
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.LOC,
            rdata=LOC(
                self.latitude, self.longitude, self.altitude, self.size, self.hp, self.vp
            ),
            ttl=self.ttl
        )

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "LOC record"
        verbose_name_plural = "LOC records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


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

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "HINFO record"
        verbose_name_plural = "HINFO records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)


class RP(dnslib.RD):
    attrs = ('mbox', 'txt')

    def __init__(self, mbox, txt):
        self.mbox = mbox
        self.txt = txt

    def pack(self, buffer):
        buffer.encode_name(self.mbox)
        buffer.encode_name(self.txt)

    def __repr__(self):
        return f"{self.mbox} {self.txt}"


class RPRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonerprecord", primary_key=True)
    mailbox = models.CharField(max_length=255)
    txt = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.mailbox = self.mailbox.lower()
        self.txt = self.txt.lower()
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

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
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.RP,
            rdata=RP(dnslib.DNSLabel(self.mailbox), dnslib.DNSLabel(self.txt)),
            ttl=self.ttl
        )

    def clean_fields(self, exclude=None):
        if "mailbox" not in exclude:
            if not all((c in DNS_ALPHABET) for c in self.mailbox):
                raise ValidationError({
                    "mailbox": "Invalid mailbox label"
                })
        if "txt" not in exclude:
            if not all((c in DNS_ALPHABET) for c in self.txt):
                raise ValidationError({
                    "txt": "Invalid txt label"
                })

        super().clean_fields(exclude=exclude)

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "RP record"
        verbose_name_plural = "RP records"
        indexes = [models.Index(fields=['record_name', 'zone'])]


class SVCBBaseRecord(DNSZoneRecord):
    port = models.PositiveSmallIntegerField(validators=[MaxValueValidator(65535)], blank=True, null=True)
    scheme = models.CharField(blank=True, null=True, max_length=255)
    priority = models.PositiveSmallIntegerField(
        validators=[MaxValueValidator(65535)], default=1,
        help_text="Record ordering, from lowest to highest, use 0 for alias mode"
    )
    target = models.CharField(
        max_length=255, help_text="A DNS name for rewritten connections", default="."
    )
    target_port = models.PositiveSmallIntegerField(validators=[MaxValueValidator(65535)], blank=True, null=True)
    target_port_mandatory = models.BooleanField(
        blank=True, help_text="Indicate that port rewriting support is required for the connection to succeed"
    )
    alpns = models.TextField(
        blank=True, null=True, help_text="A comma separated list of supported TLS ALPNs",
        verbose_name="ALPNs"
    )
    alpn_mandatory = models.BooleanField(
        blank=True, help_text="Indicate that ALPN support is required for the connection to succeed",
        verbose_name="ALPN mandatory"
    )
    no_default_alpn = models.BooleanField(
        blank=True, help_text="The server does not support the default ALPNs", verbose_name="No default ALPNs"
    )
    no_default_alpn_mandatory = models.BooleanField(
        blank=True, help_text="Indicate that support non-default ALPNs is required for the connection to succeed",
        verbose_name="No default ALPNs mandatory"
    )
    ech = models.TextField(
        blank=True, null=True, help_text="TLS Encrypted Client Hello config, Base64 encoded",
        verbose_name="TLS ECH"
    )
    ech_mandatory = models.BooleanField(
        blank=True, help_text="Indicate that TLS ECH support is required for the connection to succeed",
        verbose_name="ECH mandatory"
    )
    ipv4_hints = models.TextField(
        blank=True, help_text="A comma separated list of IPv4 addresses to reduce DNS round trips",
        verbose_name="IPv4 hints"
    )
    ipv4_hints_mandatory = models.BooleanField(
        blank=True, help_text="Indicate that IPv4 hint support is required for the connection to succeed",
        verbose_name="IPv4 hints mandatory"
    )
    ipv6_hints = models.TextField(
        blank=True, help_text="A comma separated list of IPv4 addresses to reduce DNS round trips",
        verbose_name="IPv6 hints"
    )
    ipv6_hints_mandatory = models.BooleanField(
        blank=True, help_text="Indicate that IPv6 hint support is required for the connection to succeed",
        verbose_name="IPv6 hints mandatory"
    )
    extra_params = models.TextField(
        blank=True, help_text="Extra SVCB parameters not otherwise broken out into individual fields",
        verbose_name="Extra parameters"
    )

    def __init__(self, *args, **kwargs):
        self.__alpn_cache = None
        self.__ech_cache = None
        self.__ipv4_hints_cache = None
        self.__ipv6_hints_cache = None
        self.__extra_params_cache = None
        super().__init__(*args, **kwargs)

    @property
    def alpn_data(self):
        if not self.__alpn_cache and self.alpns:
            self.__alpn_cache = svcb.ALPNData.from_str(self.alpns)
        return self.__alpn_cache

    @property
    def ech_data(self):
        if not self.__ech_cache and self.ech:
            self.__ech_cache = base64.b64decode(self.ech)
        return self.__ech_cache

    @property
    def ipv4_hints_data(self):
        if not self.__ipv4_hints_cache and self.ipv4_hints:
            self.__ipv4_hints_cache = svcb.IPv4Data.from_str(self.ipv4_hints)
        return self.__ipv4_hints_cache

    @property
    def ipv6_hints_data(self):
        if not self.__ipv6_hints_cache and self.ipv6_hints:
            self.__ipv6_hints_cache = svcb.IPv6Data.from_str(self.ipv6_hints)
        return self.__ipv6_hints_cache

    @property
    def extra_params_data(self):
        if not self.__extra_params_cache and self.extra_params:
            self.__extra_params_cache = svcb.decode_svcb_param_list(self.extra_params)
        return self.__extra_params_cache

    @property
    def has_fetch_blocked_port(self):
        if self.target_port:
            return svcb.svcb_fetch_port_blocking(self.target_port)
        return False

    def clean(self):
        super().clean()
        if self.extra_params:
            try:
                self.__extra_params_cache = svcb.decode_svcb_param_list(self.extra_params)
            except ValidationError as e:
                raise ValidationError({
                    "extra_params": e.error_list
                })

        if self.alpn_mandatory and not (self.alpns or "alpn" in self.extra_params):
            raise ValidationError({
                "alpns": "ALPNs must be specified when they are mandatory"
            })
        if self.alpns:
            if "alpn" in self.extra_params:
                raise ValidationError({
                    "extra_params": "ALPNs already defined elsewhere"
                })

            try:
                self.__alpn_cache = svcb.ALPNData.from_str(self.alpns)
            except ValidationError as e:
                raise ValidationError({
                    "alpns": e.error_list
                })

        if self.ech_mandatory and not (self.ech or "ech" in self.extra_params):
            raise ValidationError({
                "ech": "ECH must be specified when it is mandatory"
            })
        if self.ech:
            if "ech" in self.extra_params:
                raise ValidationError({
                    "extra_params": "ECH already defined elsewhere"
                })

            try:
                try:
                    self.__ech_cache = base64.b64decode(self.ech)
                except binascii.Error as e:
                    raise ValidationError(e)
            except ValidationError as e:
                raise ValidationError({
                    "ech": e.error_list
                })

        if self.no_default_alpn and not (self.alpns or "alpn" in self.extra_params):
            raise ValidationError({
                "alpns": "ALPNs must be specified when default ALPNs are ignored"
            })

        if self.target_port_mandatory and not (self.target_port or "port" in self.extra_params):
            raise ValidationError({
                "target_port": "A port must be specified when it is mandatory"
            })

        if self.ipv4_hints_mandatory and not (self.ipv4_hints or "ipv4hint" in self.extra_params):
            raise ValidationError({
                "ipv4_hints": "IPv4 hints must be specified when they are mandatory"
            })
        if self.ipv4_hints:
            if "ipv4hint" in self.extra_params:
                raise ValidationError({
                    "extra_params": "IPv4 hints already defined elsewhere"
                })

            try:
                self.__ipv4_hints_cache = svcb.IPv4Data.from_str(self.ipv4_hints)
            except ValidationError as e:
                raise ValidationError({
                    "ipv4_hints": e.error_list
                })

        if self.ipv6_hints_mandatory and not (self.ipv6_hints or "ipv6hint" in self.extra_params):
            raise ValidationError({
                "ipv6_hints": "IPv4 hints must be specified when they are mandatory"
            })
        if self.ipv6_hints:
            if "ipv6hint" in self.extra_params:
                raise ValidationError({
                    "extra_params": "IPv6 hints already defined elsewhere"
                })

            try:
                self.__ipv6_hints_cache = svcb.IPv6Data.from_str(self.ipv6_hints)
            except ValidationError as e:
                raise ValidationError({
                    "ipv6_hints": e.error_list
                })

        if self.target_port:
            if "port" in self.extra_params:
                raise ValidationError({
                    "extra_params": "Target port already defined elsewhere"
                })

        if self.alpn_mandatory or self.no_default_alpn_mandatory or self.target_port_mandatory \
                or self.ipv4_hints_mandatory or self.ipv6_hints_mandatory:
            if "mandatory" in self.extra_params:
                raise ValidationError({
                    "extra_params": "Mandatory fields already defined elsewhere"
                })

        if self.port and not self.scheme:
            raise ValidationError({
                "scheme": "Scheme must be set when a port is"
            })
        if self.scheme and not self.port:
            raise ValidationError({
                "port": "Port must be set when a scheme is"
            })

    def save(self, *args, **kwargs):
        self.target = self.target.lower()
        return super().save(*args, **kwargs)

    @property
    def svcb_record_name(self):
        if not self.port and not self.scheme:
            return self.idna_label
        else:
            if self.record_name.strip() == "@" or self.record_name.strip() == '':
                return f"_{self.port}._{self.scheme}"
            else:
                return f"_{self.port}._{self.scheme}.{self.idna_label}"

    @property
    def dns_label(self):
        record_name = self.svcb_record_name
        if record_name == "@":
            return dnslib.DNSLabel(self.zone.zone_root)
        else:
            return dnslib.DNSLabel(f"{record_name}.{self.zone.zone_root}")

    @property
    def record_label(self):
        return self.svcb_record_name

    @property
    def svcb_data(self):
        data = []
        mandatory = []
        if self.alpns:
            data.append(svcb.SVCBParam("alpn", self.alpn_data))
            if self.alpn_mandatory:
                mandatory.append(svcb.SVCBParam.PARAM_MAPPING["alpn"])
        if self.no_default_alpn:
            data.append(svcb.SVCBParam("no-default-alpn", svcb.NullParamData()))
        if self.no_default_alpn_mandatory:
            mandatory.append(svcb.SVCBParam.PARAM_MAPPING["no-default-alpn"])
        if self.ipv4_hints:
            data.append(svcb.SVCBParam("ipv4hint", self.ipv4_hints_data))
            if self.ipv4_hints_mandatory:
                mandatory.append(svcb.SVCBParam.PARAM_MAPPING["ipv4hint"])
        if self.ipv6_hints:
            data.append(svcb.SVCBParam("ipv6hint", self.ipv6_hints_data))
            if self.ipv6_hints_mandatory:
                mandatory.append(svcb.SVCBParam.PARAM_MAPPING["ipv6hint"])
        if self.target_port:
            data.append(svcb.SVCBParam("port", svcb.IntegerParamData(self.target_port)))
            if self.target_port_mandatory:
                mandatory.append(svcb.SVCBParam.PARAM_MAPPING["port"])
        if self.ech:
            data.append(svcb.SVCBParam("ech", svcb.OctetParamData(self.ech_data)))
            if self.ech_mandatory:
                mandatory.append(svcb.SVCBParam.PARAM_MAPPING["ech"])
        if self.extra_params:
            data.extend(self.extra_params_data.params)
        return svcb.SVCBParamList(data), mandatory

    @property
    def svcb_record(self):
        data, mandatory = self.svcb_data
        if mandatory:
            data.params.append(svcb.SVCBParam("mandatory", svcb.MandatoryData(mandatory)))
        return svcb.SVCB(self.priority, self.target, data)

    class Meta(DNSZoneRecord.Meta):
        abstract = True
        indexes = [models.Index(fields=['record_name', 'port', 'zone'])]


class HTTPSRecord(SVCBBaseRecord):
    port = models.PositiveSmallIntegerField(validators=[MaxValueValidator(65535)], blank=True, null=True, default=443)
    scheme = models.CharField(blank=True, null=True, max_length=255, default="https")
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonehttpsrecord", primary_key=True)
    http2_support = models.BooleanField(blank=True, verbose_name="HTTP/2 support")
    target_port_mandatory = models.BooleanField(default=False, editable=False)
    no_default_alpn_mandatory = models.BooleanField(default=False, editable=False)

    @property
    def svcb_data(self):
        data, mandatory = super().svcb_data
        if self.http2_support:
            v = data["alpn"]
            if v:
                v.data.alpns.append(b"h2")
            if not v:
                data.params.append(svcb.SVCBParam("alpn", svcb.ALPNData([b"h2"])))
        return data, mandatory

    def clean(self):
        super().clean()
        if self.http2_support:
            if self.alpn_data and b"h2" in self.alpn_data.alpns:
                raise ValidationError({
                    "alpns": "HTTP/2 support declared twice"
                })
            if "alpn" in self.extra_params:
                raise ValidationError({
                    "extra_params": "ALPNs already defined elsewhere"
                })

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

    @property
    def svcb_record_name(self):
        if self.port == 443 and self.scheme == "https":
            return self.record_name
        else:
            return super().svcb_record_name

    # @classmethod
    # def from_rr(cls, rr, zone):
    #     record_name = cls.dns_label_to_record_name(rr.rname, zone)
    #     rdata_buffer = dnslib.DNSBuffer(rr.rdata.data)
    #     return cls(
    #         zone=zone,
    #         record_name=record_name,
    #         ttl=rr.ttl,
    #         mailbox=str(rdata_buffer.decode_name()),
    #         txt=str(rdata_buffer.decode_name()),
    #     )
    #
    # def update_from_rr(self, rr):
    #     record_name = self.dns_label_to_record_name(rr.rname, self.zone)
    #     rdata_buffer = dnslib.DNSBuffer(rr.rdata.data)
    #     self.record_name = record_name
    #     self.ttl = rr.ttl
    #     self.mailbox = str(rdata_buffer.decode_name())
    #     self.txt = str(rdata_buffer.decode_name())

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.HTTPS,
            rdata=self.svcb_record,
            ttl=self.ttl
        )

    class Meta(SVCBBaseRecord.Meta):
        verbose_name = "HTTPS record"
        verbose_name_plural = "HTTPS records"


class DHCID(dnslib.RD):
    attrs = ('data')

    def __init__(self, data):
        self.data = data

    def pack(self, buffer):
        buffer.append(self.data)

    def __repr__(self):
        return base64.b64encode(self.data).decode()


class DHCIDRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_zonedhcidrecord", primary_key=True)
    data = models.BinaryField()

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    @classmethod
    def from_rr(cls, rr, zone):
        record_name = cls.dns_label_to_record_name(rr.rname, zone)
        return cls(
            zone=zone,
            record_name=record_name,
            ttl=rr.ttl,
            data=rr.rdata.data,
        )

    def update_from_rr(self, rr):
        record_name = self.dns_label_to_record_name(rr.rname, self.zone)
        self.record_name = record_name
        self.ttl = rr.ttl
        self.data = rr.rdata.data

    def to_rr(self, query_name):
        return dnslib.RR(
            query_name,
            dnslib.QTYPE.DHCID,
            rdata=DHCID(self.data),
            ttl=self.ttl
        )

    class Meta(DNSZoneRecord.Meta):
        verbose_name = "DHCID record"
        verbose_name_plural = "DHCID records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    @property
    def data_b64(self):
        return base64.b64encode(self.data).decode()


class PTRRecord(ReverseDNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_rzoneptrrecord", primary_key=True)
    pointer = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.pointer = self.pointer.lower()
        tasks.update_rzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_rzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

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
        tasks.update_rzone.delay(self.zone.id)
        self.nameserver = self.nameserver.lower()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_rzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)

    class Meta:
        verbose_name = "NS record"
        verbose_name_plural = "NS records"
        indexes = [models.Index(fields=['record_address', 'zone'])]


class GoogleState(models.Model):
    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    state = models.UUIDField(default=uuid.uuid4)
    redirect_uri = models.TextField(blank=True, null=True)

    def __str__(self):
        return str(self.state)

    class Meta:
        verbose_name = "Google state"


class GoogleInstallation(models.Model):
    user = models.OneToOneField(Account, on_delete=models.SET_NULL, blank=True, null=True)
    access_token = models.TextField(blank=True, null=True)
    access_token_expires_at = models.DateTimeField(blank=True, null=True)
    refresh_token = models.TextField(blank=True, null=True)
    refresh_token_expires_at = models.DateTimeField(blank=True, null=True)
    scopes = models.TextField(blank=True, null=True)

    def __str__(self):
        return str(self.user)

    class Meta:
        verbose_name = "Google installation"


class GitHubState(models.Model):
    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    state = models.UUIDField(default=uuid.uuid4)
    redirect_uri = models.TextField(blank=True, null=True)

    def __str__(self):
        return str(self.state)

    class Meta:
        verbose_name = "GitHub state"


class GitHubInstallation(models.Model):
    installation_id = models.PositiveIntegerField()
    user = models.ForeignKey(Account, on_delete=models.SET_NULL, blank=True, null=True)
    access_token = models.TextField(blank=True, null=True)
    access_token_expires_at = models.DateTimeField(blank=True, null=True)
    user_access_token = models.TextField(blank=True, null=True)
    user_access_token_expires_at = models.DateTimeField(blank=True, null=True)
    user_refresh_token = models.TextField(blank=True, null=True)
    user_refresh_token_expires_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return str(self.installation_id)

    class Meta:
        verbose_name = "GitHub installation"


class GitHubPagesRecord(DNSZoneRecord):
    id = as207960_utils.models.TypedUUIDField(f"hexdns_githubpagesrecord", primary_key=True)
    repo_owner = models.CharField(max_length=255, blank=True, null=True)
    repo_name = models.CharField(max_length=255, blank=True, null=True)

    def to_rrs_v4(self, query_name):
        return [dnslib.RR(
            query_name,
            dnslib.QTYPE.A,
            rdata=dnslib.A(a),
            ttl=self.ttl,
        ) for a in ["185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153"]]

    def to_rrs_v6(self, _query_name):
        return []

    class Meta:
        verbose_name = "GitHub Pages record"
        verbose_name_plural = "GitHub Pages records"
        indexes = [models.Index(fields=['record_name', 'zone'])]

    def save(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        tasks.update_fzone.delay(self.zone.id)
        return super().delete(*args, **kwargs)
