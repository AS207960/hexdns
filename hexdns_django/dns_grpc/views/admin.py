from django.contrib.auth.decorators import login_required, permission_required
from django.shortcuts import get_object_or_404, redirect, render, reverse
from django.utils import timezone

from .. import forms, models, tasks, utils


@login_required
@permission_required('dns_grpc.access_admin', raise_exception=True)
def index(request):
    fzones = models.DNSZone.objects.all()
    rzones = models.ReverseDNSZone.objects.all()
    szones = models.SecondaryDNSZone.objects.all()

    return render(request, "dns_grpc/admin/index.html", {
        "fzones": fzones,
        "rzones": rzones,
        "szones": szones,
    })


@login_required
@permission_required('dns_grpc.access_admin', raise_exception=True)
def create_zone(request):
    if request.method == "POST":
        form = forms.AdminZoneForm(request.POST)
        if form.is_valid():
            zone_root_txt = form.cleaned_data['zone_root'].lower()
            user = form.cleaned_data['user']
            zone_obj = models.DNSZone(
                zone_root=zone_root_txt,
                last_modified=timezone.now(),
                user=user,
                zsk_private=utils.get_priv_key_bytes(),
                zsk_private_ed25519=utils.get_priv_key_ed25519_bytes(),
            )
            zone_obj.save()
            tasks.add_fzone.delay(zone_obj.id)
            utils.log_usage(user, off_session=True)
            return redirect('admin_index')
    else:
        form = forms.AdminZoneForm()

    return render(request, "dns_grpc/fzone/create_zone.html", {
        "form": form
    })


@login_required
@permission_required('dns_grpc.access_admin', raise_exception=True)
def delete_zone(request, zone_id):
    user_zone = get_object_or_404(models.DNSZone, id=zone_id)

    if request.method == "POST" and request.POST.get("delete") == "true":
        utils.log_usage(user_zone.get_user(), extra=-1, off_session=True)
        user_zone.delete()
        tasks.update_catalog.delay()
        return redirect('admin_index')
    else:
        return render(request, "dns_grpc/fzone/delete_zone.html", {
            "back_url": reverse('admin_index'),
            "zone": user_zone
        })


@login_required
@permission_required('dns_grpc.access_admin', raise_exception=True)
def create_rzone(request):
    if request.method == "POST":
        form = forms.AdminReverseZoneForm(request.POST)
        if form.is_valid():
            user = form.cleaned_data['user']
            zone_obj = models.ReverseDNSZone(
                zone_root_address=form.cleaned_data['zone_root_address'],
                zone_root_prefix=form.cleaned_data['zone_root_prefix'],
                last_modified=timezone.now(),
                user=user,
                zsk_private=utils.get_priv_key_bytes(),
                zsk_private_ed25519=utils.get_priv_key_ed25519_bytes(),
            )
            zone_obj.save()
            tasks.add_rzone.delay(zone_obj.id)
            utils.log_usage(user, off_session=True)
            return redirect('admin_index')
    else:
        form = forms.AdminReverseZoneForm()

    return render(request, "dns_grpc/fzone/create_zone.html", {
        "form": form
    })


@login_required
@permission_required('dns_grpc.access_admin', raise_exception=True)
def delete_rzone(request, zone_id):
    user_zone = get_object_or_404(models.ReverseDNSZone, id=zone_id)

    if request.method == "POST" and request.POST.get("delete") == "true":
        utils.log_usage(user_zone.get_user(), extra=-1, off_session=True)
        user_zone.delete()
        tasks.update_catalog.delay()
        return redirect('admin_index')
    else:
        return render(request, "dns_grpc/rzone/delete_rzone.html", {
            "back_url": reverse('admin_index'),
            "zone": user_zone
        })


@login_required
@permission_required('dns_grpc.access_admin', raise_exception=True)
def create_szone(request):
    if request.method == "POST":
        form = forms.AdminSecondaryZoneForm(request.POST)
        if form.is_valid():
            zone_root_txt = form.cleaned_data['zone_root'].lower()
            user = form.cleaned_data['user']
            zone_obj = models.SecondaryDNSZone(
                zone_root=zone_root_txt,
                primary=form.cleaned_data['primary_server'],
                user=user,
            )
            zone_obj.save()
            utils.log_usage(user, off_session=True)
            return redirect('admin_index')
    else:
        form = forms.AdminSecondaryZoneForm()

    return render(request, "dns_grpc/fzone/create_zone.html", {
        "form": form
    })


@login_required
@permission_required('dns_grpc.access_admin', raise_exception=True)
def delete_szone(request, zone_id):
    user_zone = get_object_or_404(models.SecondaryDNSZone, id=zone_id)

    if request.method == "POST" and request.POST.get("delete") == "true":
        utils.log_usage(user_zone.get_user(), extra=-1, off_session=True)
        user_zone.delete()
        tasks.update_catalog.delay()
        return redirect('admin_index')
    else:
        return render(request, "dns_grpc/szone/delete_szone.html", {
            "back_url": reverse('admin_index'),
            "zone": user_zone
        })
