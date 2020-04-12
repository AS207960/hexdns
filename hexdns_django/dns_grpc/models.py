from django.db import models
from django.core.validators import MaxValueValidator


class DNSZone(models.Model):
    zone_root = models.CharField(max_length=255)
    last_modified = models.DateTimeField()

    class Meta:
        verbose_name = "DNS Zone"
        verbose_name_plural = "DNS Zones"

    def __str__(self):
        return self.zone_root


class ReverseDNSZone(models.Model):
    zone_root_address = models.GenericIPAddressField()
    zone_root_prefix = models.PositiveIntegerField(validators=[MaxValueValidator(128)])
    last_modified = models.DateTimeField()

    class Meta:
        verbose_name = "Reverse DNS Zone"
        verbose_name_plural = "Reverse DNS Zones"

    def __str__(self):
        return f"{self.zone_root_address}/{self.zone_root_prefix}"


class DNSZoneRecord(models.Model):
    zone = models.ForeignKey(DNSZone, on_delete=models.CASCADE)
    record_name = models.CharField(max_length=255, default="@")
    ttl = models.PositiveIntegerField()

    def __str__(self):
        return self.record_name


class ReverseDNSZoneRecord(models.Model):
    zone = models.ForeignKey(ReverseDNSZone, on_delete=models.CASCADE)
    record_address = models.GenericIPAddressField()
    ttl = models.PositiveIntegerField()

    def __str__(self):
        return self.record_address


class AddressRecord(DNSZoneRecord):
    address = models.GenericIPAddressField()
    auto_reverse = models.BooleanField(default=False)


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
    nameserver = models.CharField(max_length=255)

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


class PTRRecord(ReverseDNSZoneRecord):
    pointer = models.CharField(max_length=255)

    class Meta:
        verbose_name = "PTR record"
        verbose_name_plural = "PTR records"
