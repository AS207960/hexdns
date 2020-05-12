from django.shortcuts import render, get_object_or_404, redirect
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.conf import settings
import dnslib
import hashlib
import uuid
import base64
import ipaddress
import secrets
from . import models, forms, grpc


def make_zone_digest(zone_name: str):
    buffer = dnslib.DNSBuffer()
    nums = settings.DNSSEC_PUBKEY.public_numbers()
    rd = dnslib.DNSKEY(
        257,
        3,
        13,
        nums.x.to_bytes(32, byteorder="big") + nums.y.to_bytes(32, byteorder="big"),
    )
    buffer.encode_name(dnslib.DNSLabel(zone_name))
    rd.pack(buffer)
    digest = hashlib.sha256(buffer.data).hexdigest()
    tag = grpc.make_key_tag(settings.DNSSEC_PUBKEY, flags=257)
    return digest, tag


@login_required
def zones(request):
    user_zones = models.DNSZone.objects.filter(user=request.user)

    return render(request, "dns_grpc/zones.html", {"zones": user_zones})


@login_required
def rzones(request):
    user_zones = models.ReverseDNSZone.objects.filter(user=request.user)

    return render(request, "dns_grpc/rzones.html", {"zones": user_zones})


@login_required
def edit_zone(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    dnssec_digest, dnssec_tag = make_zone_digest(user_zone.zone_root)

    return render(
        request,
        "dns_grpc/zone.html",
        {"zone": user_zone, "dnssec_tag": dnssec_tag, "dnssec_digest": dnssec_digest},
    )


@login_required
def edit_rzone(request, zone_id):
    user_zone = get_object_or_404(models.ReverseDNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    zone_network = ipaddress.ip_network(
        (user_zone.zone_root_address, user_zone.zone_root_prefix)
    )
    zone_name = grpc.network_to_apra(zone_network)
    dnssec_digest, dnssec_tag = make_zone_digest(zone_name.label)

    return render(
        request,
        "dns_grpc/rzone.html",
        {"zone": user_zone, "dnssec_tag": dnssec_tag, "dnssec_digest": dnssec_digest}
    )


@login_required
def create_address_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.AddressRecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.AddressRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create address record", "form": record_form,},
    )


@login_required
def edit_address_record(request, record_id):
    user_record = get_object_or_404(models.AddressRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.AddressRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.AddressRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit address record", "form": record_form,},
    )


@login_required
def delete_address_record(request, record_id):
    user_record = get_object_or_404(models.AddressRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete address record", "record": user_record,},
    )


@login_required
def create_dynamic_address_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.DynamicAddressRecordForm(request.POST)
        del record_form.fields['id']
        del record_form.fields['password']
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            instance.password = secrets.token_hex(32)
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.DynamicAddressRecordForm()
        del record_form.fields['id']
        del record_form.fields['password']

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create dynamic address record", "form": record_form},
    )


@login_required
def edit_dynamic_address_record(request, record_id):
    user_record = get_object_or_404(models.DynamicAddressRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.DynamicAddressRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.DynamicAddressRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit dynamic address record", "form": record_form},
    )


@login_required
def delete_dynamic_address_record(request, record_id):
    user_record = get_object_or_404(models.DynamicAddressRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete dynamic address record", "record": user_record},
    )


@login_required
def create_cname_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.CNAMERecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.CNAMERecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create CNAME record", "form": record_form,},
    )


@login_required
def edit_cname_record(request, record_id):
    user_record = get_object_or_404(models.CNAMERecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.CNAMERecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.CNAMERecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit CNAME record", "form": record_form,},
    )


@login_required
def delete_cname_record(request, record_id):
    user_record = get_object_or_404(models.CNAMERecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete NS record", "record": user_record,},
    )


@login_required
def create_mx_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.MXRecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.MXRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create MX record", "form": record_form,},
    )


@login_required
def edit_mx_record(request, record_id):
    user_record = get_object_or_404(models.MXRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.MXRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.MXRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit MX record", "form": record_form,},
    )


@login_required
def delete_mx_record(request, record_id):
    user_record = get_object_or_404(models.MXRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete NS record", "record": user_record,},
    )


@login_required
def create_ns_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.NSRecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.NSRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create NS record", "form": record_form,},
    )


@login_required
def edit_ns_record(request, record_id):
    user_record = get_object_or_404(models.NSRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.NSRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.NSRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit NS record", "form": record_form,},
    )


@login_required
def delete_ns_record(request, record_id):
    user_record = get_object_or_404(models.NSRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete NS record", "record": user_record,},
    )


@login_required
def create_txt_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.TXTRecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.TXTRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create TXT record", "form": record_form,},
    )


@login_required
def edit_txt_record(request, record_id):
    user_record = get_object_or_404(models.TXTRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.TXTRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.TXTRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit TXT record", "form": record_form,},
    )


@login_required
def delete_txt_record(request, record_id):
    user_record = get_object_or_404(models.TXTRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete TXT record", "record": user_record,},
    )


@login_required
def create_srv_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.SRVRecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.SRVRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create SRV record", "form": record_form,},
    )


@login_required
def edit_srv_record(request, record_id):
    user_record = get_object_or_404(models.SRVRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.SRVRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.SRVRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit SRV record", "form": record_form,},
    )


@login_required
def delete_srv_record(request, record_id):
    user_record = get_object_or_404(models.SRVRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete NAPTR record", "record": user_record,},
    )


@login_required
def create_caa_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.CAARecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.CAARecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create CAA record", "form": record_form,},
    )


@login_required
def edit_caa_record(request, record_id):
    user_record = get_object_or_404(models.CAARecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.CAARecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.CAARecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit CAA record", "form": record_form,},
    )


@login_required
def delete_caa_record(request, record_id):
    user_record = get_object_or_404(models.CAARecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete CAA record", "record": user_record,},
    )


@login_required
def create_naptr_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.NAPTRRecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.NAPTRRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create NAPTR record", "form": record_form,},
    )


@login_required
def edit_naptr_record(request, record_id):
    user_record = get_object_or_404(models.NAPTRRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.NAPTRRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.NAPTRRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit NAPTR record", "form": record_form,},
    )


@login_required
def delete_naptr_record(request, record_id):
    user_record = get_object_or_404(models.NAPTRRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete NAPTR record", "record": user_record,},
    )


@login_required
def create_sshfp_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.SSHFPRecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.SSHFPRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create SSHFP record", "form": record_form,},
    )


@login_required
def edit_sshfp_record(request, record_id):
    user_record = get_object_or_404(models.SSHFPRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.SSHFPRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.SSHFPRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit SSHFP record", "form": record_form,},
    )


@login_required
def delete_sshfp_record(request, record_id):
    user_record = get_object_or_404(models.SSHFPRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete SSHFP record", "record": user_record,},
    )


@login_required
def create_ds_record(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.DSRecordForm(request.POST)
        if record_form.is_valid():
            instance = record_form.save(commit=False)
            instance.zone = user_zone
            user_zone.last_modified = timezone.now()
            instance.save()
            user_zone.save()
            return redirect("edit_zone", user_zone.id)
    else:
        record_form = forms.DSRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create DS record", "form": record_form,},
    )


@login_required
def edit_ds_record(request, record_id):
    user_record = get_object_or_404(models.DSRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.DSRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_zone", user_record.zone.id)
    else:
        record_form = forms.DSRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit DS record", "form": record_form,},
    )


@login_required
def delete_ds_record(request, record_id):
    user_record = get_object_or_404(models.DSRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_record.html",
        {"title": "Delete DS record", "record": user_record,},
    )


@login_required
def create_r_ptr_record(request, zone_id):
    user_zone = get_object_or_404(models.ReverseDNSZone, id=zone_id)

    if user_zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.ReversePTRRecordForm(
            request.POST, instance=models.PTRRecord(zone=user_zone)
        )
        if record_form.is_valid():
            record_form.save()
            user_zone.last_modified = timezone.now()
            user_zone.save()
            return redirect("edit_rzone", user_zone.id)
    else:
        record_form = forms.ReversePTRRecordForm()

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Create PTR record", "form": record_form,},
    )


@login_required
def edit_r_ptr_record(request, record_id):
    user_record = get_object_or_404(models.PTRRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        record_form = forms.ReversePTRRecordForm(request.POST, instance=user_record)
        if record_form.is_valid():
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            record_form.save()
            return redirect("edit_rzone", user_record.zone.id)
    else:
        record_form = forms.ReversePTRRecordForm(instance=user_record)

    return render(
        request,
        "dns_grpc/edit_record.html",
        {"title": "Edit PTR record", "form": record_form,},
    )


@login_required
def delete_r_ptr_record(request, record_id):
    user_record = get_object_or_404(models.PTRRecord, id=record_id)

    if user_record.zone.user != request.user:
        raise PermissionDenied

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/delete_rrecord.html",
        {"title": "Delete PTR record", "record": user_record},
    )


def get_ip(request):
    net64_net = ipaddress.IPv6Network("2a0d:1a40:7900:6::/96")
    addr = ipaddress.ip_address(request.META['REMOTE_ADDR'])
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if addr in net64_net:
            addr = ipaddress.IPv4Address(addr._ip & 0xFFFFFFFF)
    return addr


def get_header_auth(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if not auth_header:
        return None
    encoded_credentials = auth_header.split(' ', 1)
    if len(encoded_credentials) != 2:
        return None
    if encoded_credentials[0] != "Basic":
        return None
    decoded_credentials = base64.b64decode(encoded_credentials[1]).decode("utf-8").split(':', 1)
    if len(decoded_credentials) != 2:
        return None
    return decoded_credentials[0], decoded_credentials[1]


def check_ip(request):
    return HttpResponse(get_ip(request), content_type="text/plain")


@csrf_exempt
def update_ip(request):
    auth = get_header_auth(request)
    if not auth:
        return HttpResponseBadRequest()

    username, password = auth

    try:
        obj_id = uuid.UUID(username)
    except ValueError:
        return HttpResponseBadRequest("nohost")

    dyn_obj = get_object_or_404(models.DynamicAddressRecord, id=obj_id)
    if dyn_obj.password != password:
        return HttpResponseForbidden("badauth")

    if request.method == "POST":
        data = request.POST
    else:
        data = request.GET

    hostname = data.get("hostname")
    myip = data.get("myip")

    print(hostname, f"{dyn_obj.record_name}.{dyn_obj.zone.zone_root}")
    if hostname != f"{dyn_obj.record_name}.{dyn_obj.zone.zone_root}":
        return HttpResponseBadRequest("nohost")

    client_ip = get_ip(request)
    if myip:
        try:
            client_ip = ipaddress.ip_address(myip)
        except ValueError:
            return HttpResponseBadRequest()

    if isinstance(client_ip, ipaddress.IPv4Address):
        if client_ip == dyn_obj.current_ipv4:
            return HttpResponse(f"nochg {dyn_obj.current_ipv4}")
        dyn_obj.current_ipv4 = str(client_ip)
    elif isinstance(client_ip, ipaddress.IPv6Address):
        if client_ip == dyn_obj.current_ipv6:
            return HttpResponse(f"nochg {dyn_obj.current_ipv4}")
        dyn_obj.current_ipv6 = str(client_ip)

    dyn_obj.zone.last_modified = timezone.now()
    dyn_obj.save()
    dyn_obj.zone.save()

    return HttpResponse(f"good {client_ip}")
