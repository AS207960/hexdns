from django.contrib import admin
from . import models

admin.site.register(models.SecondaryDNSZoneRecord)
admin.site.register(models.AddressRecord)
admin.site.register(models.CNAMERecord)
admin.site.register(models.MXRecord)
admin.site.register(models.NSRecord)
admin.site.register(models.TXTRecord)
admin.site.register(models.SRVRecord)
admin.site.register(models.CAARecord)
admin.site.register(models.NAPTRRecord)
admin.site.register(models.SSHFPRecord)
admin.site.register(models.DSRecord)
admin.site.register(models.PTRRecord)
admin.site.register(models.Account)


@admin.register(models.DNSZone)
class DNSZoneAdmin(admin.ModelAdmin):
    list_display = ('zone_root', 'last_modified', 'active', 'charged',)


@admin.register(models.ReverseDNSZone)
class ReverseDNSZoneAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'last_modified', 'active', 'charged',)


@admin.register(models.SecondaryDNSZone)
class SecondaryDNSZoneAdmin(admin.ModelAdmin):
    list_display = ('zone_root', 'last_modified', 'active', 'charged',)
