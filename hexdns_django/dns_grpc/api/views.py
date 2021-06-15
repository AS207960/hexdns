from rest_framework import viewsets, exceptions
from django.core.exceptions import PermissionDenied
from django.utils import timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from as207960_utils.api import auth
import as207960_utils.api.permissions
import secrets
from . import serializers, permissions
from .. import models, views


class InvalidZone(exceptions.APIException):
    status_code = 400
    default_detail = 'Invalid zone'
    default_code = 'invalid_zone'


class BillingError(exceptions.APIException):
    status_code = 402
    default_detail = 'Error billing account'
    default_code = 'billing_error'


class DNSZoneViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.DNSZoneSerializer
    queryset = models.DNSZone.objects.all()
    permission_classes = [as207960_utils.api.permissions.keycloak(models.DNSZone)]

    def filter_queryset(self, queryset):
        if not isinstance(self.request.auth, auth.OAuthToken):
            raise PermissionDenied

        return models.DNSZone.get_object_list(self.request.auth.token)

    def perform_create(self, serializer):
        zone_error = views.valid_zone(serializer.validated_data['zone_root'])
        if zone_error:
            raise InvalidZone(detail=zone_error)

        status, extra = views.log_usage(self.request.user, extra=1, off_session=True)
        if status == "error":
            raise BillingError()

        priv_key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
        priv_key_bytes = priv_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ).decode()

        serializer.save(
            user=self.request.user,
            last_modified=timezone.now(),
            zsk_private=priv_key_bytes
        )

    def perform_update(self, serializer):
        serializer.save(last_modified=timezone.now())

    def perform_destroy(self, instance):
        status, extra = views.log_usage(self.request.user, off_session=True, extra=-1)
        if status == "error":
            raise BillingError()
        instance.delete()


class ReverseDNSZoneViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.ReverseDNSZoneSerializer
    queryset = models.ReverseDNSZone.objects.all()
    permission_classes = [as207960_utils.api.permissions.keycloak(models.ReverseDNSZone)]

    def filter_queryset(self, queryset):
        if not isinstance(self.request.auth, auth.OAuthToken):
            raise PermissionDenied

        return models.ReverseDNSZone.get_object_list(self.request.auth.token)

    def perform_create(self, serializer):
        status, extra = views.log_usage(self.request.user, extra=1, off_session=True)
        if status == "error":
            raise BillingError()

        priv_key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
        priv_key_bytes = priv_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ).decode()

        serializer.save(
            user=self.request.user,
            last_modified=timezone.now(),
            zsk_private=priv_key_bytes
        )

    def perform_update(self, serializer):
        serializer.save(last_modified=timezone.now())

    def perform_destroy(self, instance):
        status, extra = views.log_usage(self.request.user, off_session=True, extra=-1)
        if status == "error":
            raise BillingError()
        instance.delete()


class SecondaryDNSZoneViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.SecondaryDNSZoneSerializer
    queryset = models.SecondaryDNSZone.objects.all()
    permission_classes = [as207960_utils.api.permissions.keycloak(models.SecondaryDNSZone)]

    def filter_queryset(self, queryset):
        if not isinstance(self.request.auth, auth.OAuthToken):
            raise PermissionDenied

        return models.SecondaryDNSZone.get_object_list(self.request.auth.token)

    def perform_create(self, serializer):
        zone_error = views.valid_zone(serializer.validated_data['zone_root'])
        if zone_error:
            raise InvalidZone(detail=zone_error)

        status, extra = views.log_usage(self.request.user, extra=1, off_session=True)
        if status == "error":
            raise BillingError()

        priv_key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
        priv_key_bytes = priv_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ).decode()

        serializer.save(
            user=self.request.user,
            zsk_private=priv_key_bytes
        )

    def perform_destroy(self, instance):
        status, extra = views.log_usage(self.request.user, off_session=True, extra=-1)
        if status == "error":
            raise BillingError()
        instance.delete()


class DNSZoneRecordViewSet(viewsets.ModelViewSet):
    model_class: models.models.Model
    permission_classes = [permissions.zone_keycloak()]

    def get_queryset(self):
        return self.model_class.objects.all()

    def filter_queryset(self, queryset):
        if not isinstance(self.request.auth, auth.OAuthToken):
            raise PermissionDenied

        zones = models.DNSZone.get_object_list(self.request.auth.token)
        return self.model_class.objects.filter(zone__in=zones)

    def perform_create(self, serializer):
        serializer.save()

    def perform_update(self, serializer):
        serializer.instance.zone.last_modified = timezone.now()
        serializer.instance.zone.save()
        serializer.save()

    def perform_destroy(self, instance):
        instance.delete()


class ReverseDNSZoneRecordViewSet(viewsets.ModelViewSet):
    model_class: models.models.Model
    permission_classes = [permissions.zone_keycloak()]

    def get_queryset(self):
        return self.model_class.objects.all()

    def filter_queryset(self, queryset):
        if not isinstance(self.request.auth, auth.OAuthToken):
            raise PermissionDenied

        zones = models.ReverseDNSZone.get_object_list(self.request.auth.token)
        return self.model_class.objects.filter(zone__in=zones)

    def perform_create(self, serializer):
        serializer.save()

    def perform_update(self, serializer):
        serializer.instance.zone.last_modified = timezone.now()
        serializer.instance.zone.save()
        serializer.save()

    def perform_destroy(self, instance):
        instance.delete()


class AddressRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.AddressRecord
    serializer_class = serializers.AddressRecordSerializer


class DynamicAddressRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.DynamicAddressRecord
    serializer_class = serializers.DynamicRecordSerializer

    def perform_create(self, serializer):
        serializer.save(password=secrets.token_hex(32))


class ANAMERecordViewSet(DNSZoneRecordViewSet):
    model_class = models.ANAMERecord
    serializer_class = serializers.ANAMERecordSerializer


class CNAMERecordViewSet(DNSZoneRecordViewSet):
    model_class = models.CNAMERecord
    serializer_class = serializers.CNAMERecordSerializer


class MXRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.MXRecord
    serializer_class = serializers.MXRecordSerializer


class NSRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.NSRecord
    serializer_class = serializers.NSRecordSerializer


class TXTRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.TXTRecord
    serializer_class = serializers.TXTRecordSerializer


class SRVRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.SRVRecord
    serializer_class = serializers.SRVRecordSerializer


class CAARecordViewSet(DNSZoneRecordViewSet):
    model_class = models.CAARecord
    serializer_class = serializers.CAARecordSerializer


class NAPTRRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.NAPTRRecord
    serializer_class = serializers.NAPTRRecordSerializer


class SSHFPRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.SSHFPRecord
    serializer_class = serializers.SSHFPRecordSerializer


class DSRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.DSRecord
    serializer_class = serializers.DSRecordSerializer


class LOCRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.LOCRecord
    serializer_class = serializers.LOCRecordSerializer


class HINFORecordViewSet(DNSZoneRecordViewSet):
    model_class = models.HINFORecord
    serializer_class = serializers.HINFORecordSerializer


class RPRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.RPRecord
    serializer_class = serializers.RPRecordSerializer


class HTTPSRecordViewSet(DNSZoneRecordViewSet):
    model_class = models.HTTPSRecord
    serializer_class = serializers.HTTPSRecordSerializer


class PTRRecordViewSet(ReverseDNSZoneRecordViewSet):
    model_class = models.PTRRecord
    serializer_class = serializers.PTRRecordSerializer


class ReverseNSRecordViewSet(ReverseDNSZoneRecordViewSet):
    model_class = models.ReverseNSRecord
    serializer_class = serializers.ReverseNSRecordSerializer


class SecondaryRecordViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.zone_keycloak()]
    queryset = models.SecondaryDNSZoneRecord.objects.all()
    serializer_class = serializers.SecondaryDNSZoneRecordSerializer

    def filter_queryset(self, queryset):
        if not isinstance(self.request.auth, auth.OAuthToken):
            raise PermissionDenied

        zones = models.SecondaryDNSZone.get_object_list(self.request.auth.token)
        return models.SecondaryDNSZoneRecord.objects.filter(zone__in=zones)
