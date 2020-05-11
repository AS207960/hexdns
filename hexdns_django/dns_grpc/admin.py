from django.contrib import admin
from . import models

admin.site.register(models.DNSZone)
admin.site.register(models.ReverseDNSZone)
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
