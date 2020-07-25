from django.urls import include, path
from rest_framework import schemas
from rest_framework_nested import routers
from . import views

router = routers.DefaultRouter()
router.register(r'dns_zones', views.DNSZoneViewSet)
router.register(r'reverse_dns_zones', views.ReverseDNSZoneViewSet)
router.register(r'secondary_dns_zones', views.SecondaryDNSZoneViewSet)

zone_router = routers.NestedDefaultRouter(router, r'dns_zones', lookup='dnszone')
zone_router.register(r'address_records', views.AddressRecordViewSet, basename='dnszone-addressrecord')
zone_router.register(
    r'dynamic_address_records', views.DynamicAddressRecordViewSet, basename='dnszone-dynamicaddressrecord'
)
zone_router.register(r'aname_records', views.ANAMERecordViewSet, basename='dnszone-anamerecord')
zone_router.register(r'cname_records', views.CNAMERecordViewSet, basename='dnszone-cnamerecord')
zone_router.register(r'mx_records', views.MXRecordViewSet, basename='dnszone-mxrecord')
zone_router.register(r'ns_records', views.NSRecordViewSet, basename='dnszone-nsrecord')
zone_router.register(r'txt_records', views.TXTRecordViewSet, basename='dnszone-txtrecord')
zone_router.register(r'srv_records', views.SRVRecordViewSet, basename='dnszone-srvrecord')
zone_router.register(r'caa_records', views.CAARecordViewSet, basename='dnszone-caarecord')
zone_router.register(r'naptr_records', views.NAPTRRecordViewSet, basename='dnszone-naptrrecord')
zone_router.register(r'sshfp_records', views.SSHFPRecordViewSet, basename='dnszone-sshfprecord')
zone_router.register(r'ds_records', views.DSRecordViewSet, basename='dnszone-dsrecord')
zone_router.register(r'loc_records', views.LOCRecordViewSet, basename='dnszone-locrecord')
zone_router.register(r'hinfo_records', views.HINFORecordViewSet, basename='dnszone-hinforecord')
zone_router.register(r'rp_records', views.RPRecordViewSet, basename='dnszone-rprecord')

reverse_zone_router = routers.NestedDefaultRouter(router, r'reverse_dns_zones', lookup='dnszone')
reverse_zone_router.register(r'ptr_records', views.PTRRecordViewSet, basename='reversednszone-ptrrecord')
reverse_zone_router.register(r'ns_records', views.ReverseNSRecordViewSet, basename='reversednszone-nsrecord')

secondary_zone_router = routers.NestedDefaultRouter(router, r'secondary_dns_zones', lookup='dnszone')
secondary_zone_router.register(r'records', views.SecondaryRecordViewSet, basename='secondarydnszone-record')

urlpatterns = [
    path('', include(router.urls)),
    path('', include(zone_router.urls)),
    path('', include(reverse_zone_router.urls)),
    path('', include(secondary_zone_router.urls)),
    path('openapi', schemas.get_schema_view(
        title="Glauca HexDNS",
        version="0.0.1"
    ), name='openapi-schema'),
]
