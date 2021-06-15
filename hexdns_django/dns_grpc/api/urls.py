from django.urls import include, path
from rest_framework import schemas
from rest_framework_nested import routers
from . import views

router = routers.DefaultRouter()
router.register(r'dns_zones', views.DNSZoneViewSet)
router.register(r'reverse_dns_zones', views.ReverseDNSZoneViewSet)
router.register(r'secondary_dns_zones', views.SecondaryDNSZoneViewSet)
router.register(r'zone_address_records', views.AddressRecordViewSet, basename='addressrecord')
router.register(r'zone_dynamic_address_records', views.DynamicAddressRecordViewSet, basename='dynamicaddressrecord')
router.register(r'zone_aname_records', views.ANAMERecordViewSet, basename='anamerecord')
router.register(r'zone_cname_records', views.CNAMERecordViewSet, basename='cnamerecord')
router.register(r'zone_mx_records', views.MXRecordViewSet, basename='mxrecord')
router.register(r'zone_ns_records', views.NSRecordViewSet, basename='nsrecord')
router.register(r'zone_txt_records', views.TXTRecordViewSet, basename='txtrecord')
router.register(r'zone_srv_records', views.SRVRecordViewSet, basename='srvrecord')
router.register(r'zone_caa_records', views.CAARecordViewSet, basename='caarecord')
router.register(r'zone_naptr_records', views.NAPTRRecordViewSet, basename='naptrrecord')
router.register(r'zone_sshfp_records', views.SSHFPRecordViewSet, basename='sshfprecord')
router.register(r'zone_ds_records', views.DSRecordViewSet, basename='dsrecord')
router.register(r'zone_loc_records', views.LOCRecordViewSet, basename='locrecord')
router.register(r'zone_hinfo_records', views.HINFORecordViewSet, basename='hinforecord')
router.register(r'zone_rp_records', views.RPRecordViewSet, basename='rprecord')
router.register(r'zone_https_records', views.HTTPSRecordViewSet, basename='httpsrecord')
router.register(r'reverse_zone_ptr_records', views.PTRRecordViewSet, basename='reverse-ptrrecord')
router.register(r'reverse_zone_ns_records', views.ReverseNSRecordViewSet, basename='reverse-nsrecord')
router.register(r'secondary_zone_records', views.SecondaryRecordViewSet, basename='secondary-record')

urlpatterns = [
    path('', include(router.urls)),
    path('openapi', schemas.get_schema_view(
        title="Glauca HexDNS",
        version="0.0.1"
    ), name='openapi-schema'),
]
