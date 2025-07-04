from django.urls import path, include
from django.conf import settings
from . import views
import rest_framework.schemas

urlpatterns = [
    path("", views.fzone.zones, name="zones"),
    path("setup_subscription/", views.fzone.setup_subscription, name="setup_subscription"),
    path("create_zone/", views.fzone.create_zone, name="create_zone"),
    path("setup_domains_zone/", views.fzone.create_domains_zone, name="create_domains_zone"),
    path("setup_domain_zone_list/", views.fzone.create_domain_zone_list, name="create_domain_zone_list"),
    path("zone/<str:zone_id>/", views.fzone.edit_zone, name="edit_zone"),
    path("zone/<str:zone_id>/import_zone_file/", views.fzone.import_zone_file, name="import_zone_file"),
    path("zone/<str:zone_id>/export_zone_file/", views.fzone.export_zone_file, name="export_zone_file"),
    path("zone/<str:zone_id>/generate_dmarc/", views.fzone.generate_dmarc, name="generate_dmarc"),
    path("zone/<str:zone_id>/create_blank_spf/", views.fzone.create_blank_spf, name="create_blank_spf"),
    path("zone/<str:zone_id>/create_blank_dmarc/", views.fzone.create_blank_dmarc, name="create_blank_dmarc"),
    path("zone/<str:zone_id>/setup_gsutie/", views.fzone.setup_gsuite, name="setup_gsuite"),
    path("zone/<str:zone_id>/setup_icloud/", views.fzone.setup_icloud, name="setup_icloud"),
    path("zone/<str:zone_id>/verify_google/", views.google.verify_zone_google, name="verify_google"),
    path("zone/<str:zone_id>/setup_github_pages/", views.github.setup_github_pages, name="setup_github_pages"),
    path(
        "zone/<str:zone_id>/setup_github_pages/<str:owner>/<str:repo>/",
        views.github.setup_github_pages_repo, name="setup_github_pages_repo"
    ),
    path("zone/<str:zone_id>/cds/", views.fzone.edit_zone_cds, name="edit_zone_cds"),
    path("zone/<str:zone_id>/cds/disable/", views.fzone.disable_zone_cds, name="disable_zone_cds"),
    path("zone/<str:zone_id>/cds/enable/", views.fzone.enable_zone_cds, name="enable_zone_cds"),
    path("zone/<str:zone_id>/cds/new_cds/", views.fzone.create_zone_cds, name="create_zone_cds"),
    path("zone/<str:zone_id>/cds/new_cdnskey/", views.fzone.create_zone_cdnskey, name="create_zone_cdnskey"),
    path("zone/<str:zone_id>/cds/delete_cds/<str:cds_id>/", views.fzone.delete_zone_cds, name="delete_zone_cds"),
    path(
        "zone/<str:zone_id>/cds/delete_cdnskey/<str:cdnskey_id>/",
        views.fzone.delete_zone_cdnskey, name="delete_zone_cdnskey"
    ),
    path("zone/<str:zone_id>/tsig/", views.fzone.edit_zone_tsig, name="edit_zone_secrets"),
    path("zone/<str:zone_id>/tsig/create/", views.fzone.create_zone_secret, name="create_zone_secret"),
    path("tsig/<str:record_id>/", views.fzone.edit_zone_secret, name="edit_zone_secret"),
    path("tsig/<str:record_id>/delete/", views.fzone.delete_zone_secret, name="delete_zone_secret"),
    path("zone/<str:zone_id>/axfr/", views.fzone.edit_zone_axfr, name="edit_zone_axfr"),
    path("zone/<str:zone_id>/axfr/create_secret/", views.fzone.create_zone_axfr_secret, name="create_zone_axfr_secret"),
    path("axfr_secret/<str:record_id>/", views.fzone.edit_zone_axfr_secret, name="edit_zone_axfr_secret"),
    path("axfr_secret/<str:record_id>/delete/", views.fzone.delete_zone_axfr_secret, name="delete_zone_axfr_secret"),
    path("zone/<str:zone_id>/axfr/create_ip_acl/", views.fzone.create_zone_axfr_ip_acl, name="create_zone_axfr_ip_acl"),
    path("axfr_ip_acl/<str:record_id>/", views.fzone.edit_zone_axfr_ip_acl, name="edit_zone_axfr_ip_acl"),
    path("axfr_ip_acl/<str:record_id>/delete/", views.fzone.delete_zone_axfr_ip_acl, name="delete_zone_axfr_ip_acl"),
    path("zone/<str:zone_id>/axfr/create_notify/", views.fzone.create_zone_axfr_notify, name="create_zone_axfr_notify"),
    path("axfr_notify/<str:record_id>/", views.fzone.edit_zone_axfr_notify, name="edit_zone_axfr_notify"),
    path("axfr_notify/<str:record_id>/delete/", views.fzone.delete_zone_axfr_notify, name="delete_zone_axfr_notify"),
    path("zone/<str:zone_id>/custom_ns/", views.fzone.edit_zone_custom_ns, name="edit_custom_ns"),
    path("zone/<str:zone_id>/custom_ns/create/", views.fzone.create_zone_custom_ns, name="create_zone_custom_ns"),
    path("custom_ns/<str:record_id>/", views.fzone.edit_zone_custom_ns_record, name="edit_custom_ns_record"),
    path("custom_ns/<str:record_id>/delete/", views.fzone.delete_zone_custom_ns_record, name="delete_custom_ns_record"),
    path("delete_zone/<str:zone_id>/", views.fzone.delete_zone, name="delete_zone"),
    path("zone/<str:zone_id>/new_address/", views.fzone.create_address_record, name="create_address_record"),
    path(
        "zone/<str:zone_id>/new_dynamic_address/",
        views.fzone.create_dynamic_address_record, name="create_dynamic_address_record",
    ),
    path("zone/<str:zone_id>/new_aname/", views.fzone.create_aname_record, name="create_aname_record"),
    path("zone/<str:zone_id>/new_redirect/", views.fzone.create_redirect_record, name="create_redirect_record"),
    path("zone/<str:zone_id>/new_cname/", views.fzone.create_cname_record, name="create_cname_record"),
    path("zone/<str:zone_id>/new_mx/", views.fzone.create_mx_record, name="create_mx_record"),
    path("zone/<str:zone_id>/new_ns/", views.fzone.create_ns_record, name="create_ns_record"),
    path("zone/<str:zone_id>/new_txt/", views.fzone.create_txt_record, name="create_txt_record"),
    path("zone/<str:zone_id>/new_srv/", views.fzone.create_srv_record, name="create_srv_record"),
    path("zone/<str:zone_id>/new_caa/", views.fzone.create_caa_record, name="create_caa_record"),
    path("zone/<str:zone_id>/new_naptr/", views.fzone.create_naptr_record, name="create_naptr_record"),
    path("zone/<str:zone_id>/new_sshfp/", views.fzone.create_sshfp_record, name="create_sshfp_record"),
    path("zone/<str:zone_id>/new_ds/", views.fzone.create_ds_record, name="create_ds_record"),
    path("zone/<str:zone_id>/new_dnskey/", views.fzone.create_dnskey_record, name="create_dnskey_record"),
    path("zone/<str:zone_id>/new_loc/", views.fzone.create_loc_record, name="create_loc_record"),
    path("zone/<str:zone_id>/new_hinfo/", views.fzone.create_hinfo_record, name="create_hinfo_record"),
    path("zone/<str:zone_id>/new_rp/", views.fzone.create_rp_record, name="create_rp_record"),
    path("zone/<str:zone_id>/new_https/", views.fzone.create_https_record, name="create_https_record"),
    path("zone/<str:zone_id>/new_tlsa/", views.fzone.create_tlsa_record, name="create_tlsa_record"),
    path("records/address/<str:record_id>/", views.fzone.edit_address_record, name="edit_address_record"),
    path("records/address/<str:record_id>/copy/", views.fzone.copy_address_record, name="copy_address_record"),
    path("records/address/<str:record_id>/delete/", views.fzone.delete_address_record, name="delete_address_record"),
    path(
        "records/dynamic_address/<str:record_id>/",
        views.fzone.edit_dynamic_address_record, name="edit_dynamic_address_record",
    ),
    path(
        "records/dynamic_address/<str:record_id>/copy/",
        views.fzone.copy_dynamic_address_record, name="copy_dynamic_address_record",
    ),
    path(
        "records/dynamic_address/<str:record_id>/delete/",
        views.fzone.delete_dynamic_address_record, name="delete_dynamic_address_record",
    ),
    path("records/aname/<str:record_id>/", views.fzone.edit_aname_record, name="edit_aname_record"),
    path("records/aname/<str:record_id>/copy/", views.fzone.copy_aname_record, name="copy_aname_record"),
    path("records/aname/<str:record_id>/delete/", views.fzone.delete_aname_record, name="delete_aname_record"),
    path("records/redirect/<str:record_id>/", views.fzone.edit_redirect_record, name="edit_redirect_record"),
    path("records/redirect/<str:record_id>/copy/", views.fzone.copy_redirect_record, name="copy_redirect_record"),
    path("records/redirect/<str:record_id>/delete/", views.fzone.delete_redirect_record, name="delete_redirect_record"),
    path("records/cname/<str:record_id>/", views.fzone.edit_cname_record, name="edit_cname_record"),
    path("records/cname/<str:record_id>/copy/", views.fzone.copy_cname_record, name="copy_cname_record"),
    path("records/cname/<str:record_id>/delete/", views.fzone.delete_cname_record, name="delete_cname_record"),
    path("records/mx/<str:record_id>/", views.fzone.edit_mx_record, name="edit_mx_record"),
    path("records/mx/<str:record_id>/copy/", views.fzone.copy_mx_record, name="copy_mx_record"),
    path("records/mx/<str:record_id>/delete/", views.fzone.delete_mx_record, name="delete_mx_record"),
    path("records/ns/<str:record_id>/", views.fzone.edit_ns_record, name="edit_ns_record"),
    path("records/ns/<str:record_id>/cope/", views.fzone.copy_ns_record, name="copy_ns_record"),
    path("records/ns/<str:record_id>/delete/", views.fzone.delete_ns_record, name="delete_ns_record"),
    path("records/txt/<str:record_id>/", views.fzone.edit_txt_record, name="edit_txt_record"),
    path("records/txt/<str:record_id>/copy/", views.fzone.copy_txt_record, name="copy_txt_record"),
    path("records/txt/<str:record_id>/delete/", views.fzone.delete_txt_record, name="delete_txt_record"),
    path("records/srv/<str:record_id>/", views.fzone.edit_srv_record, name="edit_srv_record"),
    path("records/srv/<str:record_id>/copy/", views.fzone.copy_srv_record, name="copy_srv_record"),
    path("records/srv/<str:record_id>/delete/", views.fzone.delete_srv_record, name="delete_srv_record"),
    path("records/caa/<str:record_id>/", views.fzone.edit_caa_record, name="edit_caa_record"),
    path("records/caa/<str:record_id>/copy/", views.fzone.copy_caa_record, name="copy_caa_record"),
    path("records/caa/<str:record_id>/delete/", views.fzone.delete_caa_record, name="delete_caa_record"),
    path("records/naptr/<str:record_id>/", views.fzone.edit_naptr_record, name="edit_naptr_record"),
    path("records/naptr/<str:record_id>/copy/", views.fzone.copy_naptr_record, name="copy_naptr_record"),
    path("records/naptr/<str:record_id>/delete/", views.fzone.delete_naptr_record, name="delete_naptr_record"),
    path("records/sshfp/<str:record_id>/", views.fzone.edit_sshfp_record, name="edit_sshfp_record"),
    path("records/sshfp/<str:record_id>/copy/", views.fzone.copy_sshfp_record, name="copy_sshfp_record"),
    path("records/sshfp/<str:record_id>/delete/", views.fzone.delete_sshfp_record, name="delete_sshfp_record"),
    path("records/ds/<str:record_id>/", views.fzone.edit_ds_record, name="edit_ds_record"),
    path("records/ds/<str:record_id>/copy/", views.fzone.copy_ds_record, name="copy_ds_record"),
    path("records/ds/<str:record_id>/delete/", views.fzone.delete_ds_record, name="delete_ds_record"),
    path("records/dnskey/<str:record_id>/", views.fzone.edit_dnskey_record, name="edit_dnskey_record"),
    path("records/dnskey/<str:record_id>/copy/", views.fzone.copy_dnskey_record, name="copy_dnskey_record"),
    path("records/dnskey/<str:record_id>/delete/", views.fzone.delete_dnskey_record, name="delete_dnskey_record"),
    path("records/loc/<str:record_id>/", views.fzone.edit_loc_record, name="edit_loc_record"),
    path("records/loc/<str:record_id>/copy/", views.fzone.copy_loc_record, name="copy_loc_record"),
    path("records/loc/<str:record_id>/delete/", views.fzone.delete_loc_record, name="delete_loc_record"),
    path("records/hinfo/<str:record_id>/", views.fzone.edit_hinfo_record, name="edit_hinfo_record"),
    path("records/hinfo/<str:record_id>/copy/", views.fzone.copy_hinfo_record, name="copy_hinfo_record"),
    path("records/hinfo/<str:record_id>/delete/", views.fzone.delete_hinfo_record, name="delete_hinfo_record"),
    path("records/rp/<str:record_id>/", views.fzone.edit_rp_record, name="edit_rp_record"),
    path("records/rp/<str:record_id>/copy/", views.fzone.copy_rp_record, name="copy_rp_record"),
    path("records/rp/<str:record_id>/delete/", views.fzone.delete_rp_record, name="delete_rp_record"),
    path("records/https/<str:record_id>/", views.fzone.edit_https_record, name="edit_https_record"),
    path("records/https/<str:record_id>/copy/", views.fzone.copy_https_record, name="copy_https_record"),
    path("records/https/<str:record_id>/delete/", views.fzone.delete_https_record, name="delete_https_record"),
    path("records/tlsa/<str:record_id>/", views.fzone.edit_tlsa_record, name="edit_tlsa_record"),
    path("records/tlsa/<str:record_id>/copy/", views.fzone.copy_tlsa_record, name="copy_tlsa_record"),
    path("records/tlsa/<str:record_id>/delete/", views.fzone.delete_tlsa_record, name="delete_tlsa_record"),
    path("records/github/<str:record_id>/", views.github.edit_github_pages_record, name="edit_github_record"),
    path(
        "records/github/<str:record_id>/rebuild/",
        views.github.github_pages_record_rebuild, name="github_record_rebuild"
    ),
    path(
        "records/github/<str:record_id>/delete/", views.github.delete_github_pages_record, name="delete_github_record"
    ),
    path("reverse/", views.rzone.rzones, name="rzones"),
    path("rzone/<str:zone_id>/", views.rzone.edit_rzone, name="edit_rzone"),
    path("rzone/<str:zone_id>/new_ptr/", views.rzone.create_r_ptr_record, name="create_r_ptr_record"),
    path("rzone/<str:zone_id>/new_ns/", views.rzone.create_r_ns_record, name="create_r_ns_record"),
    path("rrecords/ptr/<str:record_id>/", views.rzone.edit_r_ptr_record, name="edit_r_ptr_record"),
    path("rrecords/ptr/<str:record_id>/copy/", views.rzone.copy_r_ptr_record, name="copy_r_ptr_record"),
    path("rrecords/ptr/<str:record_id>/delete/", views.rzone.delete_r_ptr_record, name="delete_r_ptr_record"),
    path("rrecords/ns/<str:record_id>/", views.rzone.edit_r_ns_record, name="edit_r_ns_record"),
    path("rrecords/ns/<str:record_id>/copy/", views.rzone.copy_r_ns_record, name="copy_r_ns_record"),
    path("rrecords/ns/<str:record_id>/delete/", views.rzone.delete_r_ns_record, name="delete_r_ns_record"),
    path("create_szone/", views.szone.create_szone, name="new_szone"),
    path("secondary/", views.szone.szones, name="szones"),
    path("szone/<str:zone_id>/", views.szone.view_szone, name="view_szone"),
    path("szone/<str:zone_id>/edit/", views.szone.edit_szone, name="edit_szone"),
    path("delete_szone/<str:zone_id>/", views.szone.delete_szone, name="delete_szone"),
    path("github_oauth_login/", views.github.oauth_login, name="github_oauth_login"),
    path("github_oauth_callback/", views.github.oauth_callback, name="github_oauth_callback"),
    path("github_app_webhook/", views.github.webhook),
    path("google_oauth_callback/", views.google.oauth_callback, name="google_oauth_callback"),
    path("dns_admin/", views.admin.index, name="admin_index"),
    path("dns_admin/create_zone/", views.admin.create_zone, name="admin_create_zone"),
    path("dns_admin/create_rzone/", views.admin.create_rzone, name="admin_create_rzone"),
    path("dns_admin/create_szone/", views.admin.create_szone, name="admin_create_szone"),
    path("dns_admin/zone/<str:zone_id>/delete/", views.admin.delete_zone, name="admin_delete_zone"),
    path("dns_admin/rzone/<str:zone_id>/delete/", views.admin.delete_rzone, name="admin_delete_rzone"),
    path("dns_admin/szone/<str:zone_id>/delete/", views.admin.delete_szone, name="admin_delete_szone"),
    path("checkip", views.dyndns.check_ip, name="check_ip"),
    path("nic/update", views.dyndns.update_ip, name="update_ip"),

    path('postal/webhook/', views.postal.postal),

    path(
        "api/openapi", rest_framework.schemas.get_schema_view(
            title="Glauca HexDNS API",
            urlconf='dns_grpc.api.urls',
            url=f"{settings.EXTERNAL_URL_BASE}/api"
        ), name="openapi-schema",
    ),
    path('api/', include('dns_grpc.api.urls')),

]
