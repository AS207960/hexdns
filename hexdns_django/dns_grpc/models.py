from django.db import models
from django.conf import settings
from django.shortcuts import reverse
from django.contrib.auth import get_user_model
import django_keycloak_auth.clients
import uuid
import ipaddress
import sshpubkeys
import base64
import dnslib
import binascii
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator


def sync_resource_to_keycloak(self, display_name, resource_type, scopes, urn, view_name, super_save, args, kwargs):
    uma_client = django_keycloak_auth.clients.get_uma_client()
    token = django_keycloak_auth.clients.get_access_token()
    created = False

    if not self.pk:
        created = True
    super_save(*args, **kwargs)

    create_kwargs = {
        "name": f"{resource_type}_{self.id}",
        "displayName": f"{display_name}: {str(self)}",
        "ownerManagedAccess": True,
        "scopes": scopes,
        "type": urn,
        "uri": reverse(view_name, args=(self.id,)) if view_name else None,
    }

    if created or not self.resource_id:
        if self.user:
            create_kwargs['owner'] = self.user.username

        d = uma_client.resource_set_create(
            token,
            **create_kwargs
        )
        self.resource_id = d['_id']
        super_save()
    else:
        uma_client.resource_set_update(
            token,
            id=self.resource_id,
            **create_kwargs
        )


def delete_resource(resource_id):
    uma_client = django_keycloak_auth.clients.get_uma_client()
    token = django_keycloak_auth.clients.get_access_token()
    uma_client.resource_set_delete(token, resource_id)


def get_object_ids(access_token, resource_type, action):
    scope_name = f"{action}-{resource_type}"
    permissions = django_keycloak_auth.clients.get_authz_client().get_permissions(access_token)
    permissions = permissions.get("permissions", [])
    permissions = filter(
        lambda p: scope_name in p.get('scopes', []) and p.get('rsname', "").startswith(f"{resource_type}_"),
        permissions
    )
    object_ids = list(map(lambda p: p['rsname'][len(f"{resource_type}_"):], permissions))
    return object_ids


def eval_permission(token, resource, scope, submit_request=False):
    resource = str(resource)
    permissions = django_keycloak_auth.clients.get_authz_client().get_permissions(
        token=token,
        resource_scopes_tuples=[(resource, scope)],
        submit_request=submit_request
    )

    for permission in permissions.get('permissions', []):
        for scope in permission.get('scopes', []):
            if permission.get('rsid') == resource and scope == scope:
                return True

    return False


def get_resource_owner(resource_id):
    uma_client = django_keycloak_auth.clients.get_uma_client()
    token = django_keycloak_auth.clients.get_access_token()
    resource = uma_client.resource_set_read(token, resource_id)
    owner = resource.get("owner", {}).get("id")
    user = get_user_model().objects.filter(username=owner).first()
    return user


class Account(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    subscription_id = models.UUIDField(blank=True, null=True)

    def __str__(self):
        return str(self.user)


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_profile(sender, instance, created, **kwargs):
    if created or not hasattr(instance, "account"):
        Account.objects.create(user=instance)
    instance.account.save()


class DNSZone(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    zone_root = models.CharField(max_length=255)
    last_modified = models.DateTimeField()
    zsk_private = models.TextField(blank=True, null=True)
    charged = models.BooleanField(default=True, blank=True)
    active = models.BooleanField(default=False, blank=True)
    resource_id = models.UUIDField(null=True)

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(pk__in=get_object_ids(access_token, 'zone', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-zone"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, f"zone", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-zone"
        return eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        self.zone_root = self.zone_root.lower()
        sync_resource_to_keycloak(
            self,
            display_name="Zone", resource_type="zone", scopes=[
                'view-zone',
                'edit-zone',
                'delete-zone',
            ],
            urn="urn:as207960:hexdns:zone", super_save=super().save, view_name='edit_zone',
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        delete_resource(self.resource_id)

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
    zsk_private = models.TextField(blank=True, null=True)
    charged = models.BooleanField(default=True, blank=True)
    active = models.BooleanField(default=True, blank=True)
    resource_id = models.UUIDField(null=True)

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(pk__in=get_object_ids(access_token, 'reverse-zone', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-reverse-zone"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, f"reverse-zone", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-reverse-zone"
        return eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        sync_resource_to_keycloak(
            self,
            display_name="Reverse zone", resource_type="reverse-zone", scopes=[
                'view-reverse-zone',
                'edit-reverse-zone',
                'delete-reverse-zone',
            ],
            urn="urn:as207960:hexdns:reverse_zone", super_save=super().save, view_name='edit_rzone',
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        delete_resource(self.resource_id)

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


class SecondaryDNSZone(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    zone_root = models.CharField(max_length=255)
    serial = models.PositiveIntegerField(null=True)
    primary = models.CharField(max_length=255)
    charged = models.BooleanField(default=True, blank=True)
    active = models.BooleanField(default=False, blank=True)
    error = models.BooleanField(default=False, blank=True)
    resource_id = models.UUIDField(null=True)

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    @classmethod
    def get_object_list(cls, access_token: str, action='view'):
        return cls.objects.filter(pk__in=get_object_ids(access_token, 'secondary-zone', action))

    @classmethod
    def has_class_scope(cls, access_token: str, action='view'):
        scope_name = f"{action}-secondary-zone"
        return django_keycloak_auth.clients.get_authz_client() \
            .eval_permission(access_token, f"secondary-zone", scope_name)

    def has_scope(self, access_token: str, action='view'):
        scope_name = f"{action}-secondary-zone"
        return eval_permission(access_token, self.resource_id, scope_name)

    def save(self, *args, **kwargs):
        self.zone_root = self.zone_root.lower()
        sync_resource_to_keycloak(
            self,
            display_name="Secondary zone", resource_type="secondary-zone", scopes=[
                'view-secondary-zone',
                'edit-secondary-zone',
                'delete-secondary-zone',
            ],
            urn="urn:as207960:hexdns:secondary_zone", super_save=super().save, view_name='view_szone',
            args=args, kwargs=kwargs
        )

    def delete(self, *args, **kwargs):
        super().delete(*args, *kwargs)
        delete_resource(self.resource_id)

    class Meta:
        verbose_name = "Secondary DNS Zone"
        verbose_name_plural = "Secondary DNS Zones"

    def __str__(self):
        return self.zone_root


class SecondaryDNSZoneRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    zone = models.ForeignKey(SecondaryDNSZone, on_delete=models.CASCADE)
    record_name = models.CharField(max_length=255)
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)")
    rtype = models.PositiveSmallIntegerField()
    rdata = models.BinaryField()

    class Meta:
        verbose_name = "Secondary DNS Zone Record"
        verbose_name_plural = "Secondary DNS Zones Record"
        ordering = ('record_name', 'rtype')

    def __str__(self):
        return f"{self.record_name} IN {self.rtype_name} {self.ttl}"

    @property
    def rtype_name(self):
        return dnslib.QTYPE.get(self.rtype)


class DNSZoneRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
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

    def __str__(self):
        return self.record_name


class ReverseDNSZoneRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE)
    record_address = models.GenericIPAddressField()
    ttl = models.PositiveIntegerField(verbose_name="Time to Live (seconds)", default=3600)

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


class ANAMERecord(DNSZoneRecord):
    alias = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.alias = self.alias.lower()
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = "ANAME record"
        verbose_name_plural = "ANAME records"


class CNAMERecord(DNSZoneRecord):
    alias = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.alias = self.alias.lower()
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = "CNAME record"
        verbose_name_plural = "CNAME records"


class MXRecord(DNSZoneRecord):
    exchange = models.CharField(max_length=255)
    priority = models.PositiveIntegerField(validators=[MaxValueValidator(65535)])

    def save(self, *args, **kwargs):
        self.exchange = self.exchange.lower()
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = "MX record"
        verbose_name_plural = "MX records"


class NSRecord(DNSZoneRecord):
    nameserver = models.CharField(max_length=255, verbose_name="Name server")

    def save(self, *args, **kwargs):
        self.nameserver = self.nameserver.lower()
        return super().save(*args, **kwargs)

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


class LOCRecord(DNSZoneRecord):
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

    class Meta:
        verbose_name = "LOC record"
        verbose_name_plural = "LOC records"


class HINFORecord(DNSZoneRecord):
    cpu = models.CharField(max_length=255, verbose_name="CPU")
    os = models.CharField(max_length=255, verbose_name="OS")

    class Meta:
        verbose_name = "HINFO record"
        verbose_name_plural = "HINFO records"


class RPRecord(DNSZoneRecord):
    mailbox = models.CharField(max_length=255)
    txt = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.mailbox = self.mailbox.lower()
        self.txt = self.txt.lower()
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = "RP record"
        verbose_name_plural = "RP records"


class PTRRecord(ReverseDNSZoneRecord):
    pointer = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.pointer = self.pointer.lower()
        return super().save(*args, **kwargs)

    class Meta:
        verbose_name = "PTR record"
        verbose_name_plural = "PTR records"


class ReverseNSRecord(ReverseDNSZoneRecord):
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
