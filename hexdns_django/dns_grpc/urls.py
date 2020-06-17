from django.urls import path
from . import views

urlpatterns = [
    path("", views.zones, name="zones"),
    path("reverse/", views.rzones, name="rzones"),
    path("create_zone/", views.create_zone, name="create_zone"),
    path("zone/<uuid:zone_id>/", views.edit_zone, name="edit_zone"),
    path("zone/<uuid:zone_id>/import_zone_file/", views.import_zone_file, name="import_zone_file"),
    path("zone/<uuid:zone_id>/generate_dmarc/", views.generate_dmarc, name="generate_dmarc"),
    path("zone/<uuid:zone_id>/setup_gsutie/", views.setup_gsuite, name="setup_gsuite"),
    path("delete_zone/<uuid:zone_id>/", views.delete_zone, name="delete_zone"),
    path(
        "zone/<uuid:zone_id>/new_address/",
        views.create_address_record,
        name="create_address_record",
    ),
    path(
        "zone/<uuid:zone_id>/new_dynamic_address/",
        views.create_dynamic_address_record,
        name="create_dynamic_address_record",
    ),
    path(
        "zone/<uuid:zone_id>/new_cname/",
        views.create_cname_record,
        name="create_cname_record",
    ),
    path(
        "zone/<uuid:zone_id>/new_mx/", views.create_mx_record, name="create_mx_record"
    ),
    path(
        "zone/<uuid:zone_id>/new_ns/", views.create_ns_record, name="create_ns_record"
    ),
    path(
        "zone/<uuid:zone_id>/new_txt/",
        views.create_txt_record,
        name="create_txt_record",
    ),
    path(
        "zone/<uuid:zone_id>/new_srv/",
        views.create_srv_record,
        name="create_srv_record",
    ),
    path(
        "zone/<uuid:zone_id>/new_caa/",
        views.create_caa_record,
        name="create_caa_record",
    ),
    path(
        "zone/<uuid:zone_id>/new_naptr/",
        views.create_naptr_record,
        name="create_naptr_record",
    ),
    path(
        "zone/<uuid:zone_id>/new_sshfp/",
        views.create_sshfp_record,
        name="create_sshfp_record",
    ),
    path(
        "zone/<uuid:zone_id>/new_ds/", views.create_ds_record, name="create_ds_record"
    ),
    path(
        "records/address/<uuid:record_id>/",
        views.edit_address_record,
        name="edit_address_record",
    ),
    path(
        "records/address/<uuid:record_id>/delete/",
        views.delete_address_record,
        name="delete_address_record",
    ),
    path(
        "records/dynamic_address/<uuid:record_id>/",
        views.edit_dynamic_address_record,
        name="edit_dynamic_address_record",
    ),
    path(
        "records/dynamic_address/<uuid:record_id>/delete/",
        views.delete_dynamic_address_record,
        name="delete_dynamic_address_record",
    ),
    path(
        "records/cname/<uuid:record_id>/",
        views.edit_cname_record,
        name="edit_cname_record",
    ),
    path(
        "records/cname/<uuid:record_id>/delete/",
        views.delete_cname_record,
        name="delete_cname_record",
    ),
    path("records/mx/<uuid:record_id>/", views.edit_mx_record, name="edit_mx_record"),
    path(
        "records/mx/<uuid:record_id>/delete/",
        views.delete_mx_record,
        name="delete_mx_record",
    ),
    path("records/ns/<uuid:record_id>/", views.edit_ns_record, name="edit_ns_record"),
    path(
        "records/ns/<uuid:record_id>/delete/",
        views.delete_ns_record,
        name="delete_ns_record",
    ),
    path(
        "records/txt/<uuid:record_id>/", views.edit_txt_record, name="edit_txt_record"
    ),
    path(
        "records/txt/<uuid:record_id>/delete/",
        views.delete_txt_record,
        name="delete_txt_record",
    ),
    path(
        "records/srv/<uuid:record_id>/", views.edit_srv_record, name="edit_srv_record"
    ),
    path(
        "records/srv/<uuid:record_id>/delete/",
        views.delete_srv_record,
        name="delete_srv_record",
    ),
    path(
        "records/caa/<uuid:record_id>/", views.edit_caa_record, name="edit_caa_record"
    ),
    path(
        "records/caa/<uuid:record_id>/delete/",
        views.delete_caa_record,
        name="delete_caa_record",
    ),
    path(
        "records/naptr/<uuid:record_id>/",
        views.edit_naptr_record,
        name="edit_naptr_record",
    ),
    path(
        "records/naptr/<uuid:record_id>/delete/",
        views.delete_naptr_record,
        name="delete_naptr_record",
    ),
    path(
        "records/sshfp/<uuid:record_id>/",
        views.edit_sshfp_record,
        name="edit_sshfp_record",
    ),
    path(
        "records/sshfp/<uuid:record_id>/delete/",
        views.delete_sshfp_record,
        name="delete_sshfp_record",
    ),
    path("records/ds/<uuid:record_id>/", views.edit_ds_record, name="edit_ds_record"),
    path(
        "records/ds/<uuid:record_id>/delete/",
        views.delete_ds_record,
        name="delete_ds_record",
    ),
    path("rzone/<uuid:zone_id>/", views.edit_rzone, name="edit_rzone"),
    path(
        "rzone/<uuid:zone_id>/new_ptr/",
        views.create_r_ptr_record,
        name="create_r_ptr_record",
    ),
    path(
        "rrecords/ptr/<uuid:record_id>/",
        views.edit_r_ptr_record,
        name="edit_r_ptr_record",
    ),
    path(
        "rrecords/ptr/<uuid:record_id>/delete/",
        views.delete_r_ptr_record,
        name="delete_r_ptr_record",
    ),
    path("checkip", views.check_ip, name="check_ip"),
    path("nic/update", views.update_ip, name="update_ip"),
]
