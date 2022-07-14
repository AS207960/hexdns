from rest_framework import serializers
from django.conf import settings
import base64
import ipaddress
import collections
from .. import models, views, tasks


class WriteOnceMixin:
    def get_fields(self):
        fields = super().get_fields()

        if 'update' in getattr(self.context.get('view'), 'action', ''):
            self._set_write_once_fields(fields)
            self._set_write_after_fields(fields)

        return fields

    def _set_write_once_fields(self, fields):
        write_once_fields = getattr(self.Meta, 'write_once_fields', None)
        if not write_once_fields:
            return

        if not isinstance(write_once_fields, (list, tuple)):
            raise TypeError(
                'The `write_once_fields` option must be a list or tuple. '
                'Got {}.'.format(type(write_once_fields).__name__)
            )

        for field_name in write_once_fields:
            fields[field_name].read_only = True

    def _set_write_after_fields(self, fields):
        write_after_fields = getattr(self.Meta, 'write_after_fields', None)
        if not write_after_fields:
            return

        if not isinstance(write_after_fields, (list, tuple)):
            raise TypeError(
                'The `write_after_fields` option must be a list or tuple. '
                'Got {}.'.format(type(write_after_fields).__name__)
            )

        for field_name in write_after_fields:
            fields[field_name].read_only = False


class PermissionPrimaryKeyRelatedFieldValidator:
    requires_context = True

    def __call__(self, value, ctx):
        if not value.has_scope(ctx.auth_token, 'view'):
            raise serializers.ValidationError("you don't have permission to reference this object")


class PermissionPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    def __init__(self, model, **kwargs):
        self.model = model
        self.auth_token = None
        super().__init__(queryset=model.objects.all(), **kwargs)

    def get_choices(self, cutoff=None):
        if self.auth_token:
            queryset = self.model.get_object_list(self.auth_token)
        else:
            queryset = self.get_queryset()

        if queryset is None:
            return {}

        if cutoff is not None:
            queryset = queryset[:cutoff]

        return collections.OrderedDict([
            (
                self.to_representation(item),
                self.display_value(item)
            )
            for item in queryset
        ])

    def get_validators(self):
        validators = super().get_validators()
        validators.append(PermissionPrimaryKeyRelatedFieldValidator())
        return validators


class ZoneRecordSerializer(WriteOnceMixin, serializers.ModelSerializer):
    zone_url = serializers.HyperlinkedRelatedField(
        view_name='dnszone-detail',
        source='zone',
        read_only=True,
    )


class AddressRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='addressrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.AddressRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'address', 'auto_reverse', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class DynamicRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='dynamicaddressrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.DynamicAddressRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'current_ipv4', 'current_ipv6', 'password', 'ttl',)
        read_only_fields = ('id', 'current_ipv4', 'current_ipv6', 'password')
        write_once_fields = ('zone',)


class ANAMERecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='anamerecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.ANAMERecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'alias', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class CNAMERecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='cnamerecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.CNAMERecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'alias', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class MXRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='mxrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.MXRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'exchange', 'priority', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class NSRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='nsrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.NSRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'nameserver', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class TXTRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='txtrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.TXTRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'data', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class SRVRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='srvrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.SRVRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'priority', 'weight', 'port', 'target', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class CAARecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='caarecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.CAARecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'flag', 'tag', 'value', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class NAPTRRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='naptrrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.NAPTRRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'order', 'preference', 'flags', 'service', 'regexp',
                  'replacement', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class SSHFPRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='sshfprecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.SSHFPRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'host_key', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class DSRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='dsrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.DSRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'key_tag', 'algorithm', 'digest_type', 'digest',
                  'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class LOCRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='locrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.LOCRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'latitude', 'longitude', 'altitude', 'size', 'hp',
                  'vp', 'ttl',)
        read_only_fields = ('id', 'zone',)


class HINFORecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='hinforecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.HINFORecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'cpu', 'os', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class RPRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='rprecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.RPRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'mailbox', 'txt', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class HTTPSRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='httpsrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.DNSZone)

    class Meta:
        model = models.HTTPSRecord
        fields = (
            'url', 'id', 'zone', 'zone_url', 'record_name', 'port', 'scheme', 'ttl', 'priority',
            'target', 'target_port', 'http2_support', 'ech', 'ech_mandatory', 'alpns', 'alpn_mandatory',
            'no_default_alpn', 'ipv4_hints', 'ipv4_hints_mandatory', 'ipv6_hints', 'ipv6_hints_mandatory',
            'extra_params',
        )
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class DNSSECKeySerializer(serializers.Serializer):
    flags = serializers.IntegerField(read_only=True)
    protocol = serializers.IntegerField(read_only=True)
    algorithm = serializers.IntegerField(read_only=True)
    public_key = serializers.CharField(read_only=True)


class DNSSECSerializer(serializers.Serializer):
    key_tag = serializers.IntegerField(read_only=True)
    algorithm = serializers.IntegerField(read_only=True)
    digest_type = serializers.IntegerField(read_only=True)
    digest = serializers.CharField(read_only=True)
    key = DNSSECKeySerializer(read_only=True)


class DNSZoneSerializer(WriteOnceMixin, serializers.ModelSerializer):
    class Meta:
        model = models.DNSZone
        fields = ('url', 'id', 'zone_root', 'last_modified', 'active', 'dnssec', 'address_records',
                  'dynamic_address_records', 'aname_records', 'cname_records', 'mx_records', 'ns_records',
                  'txt_records', 'srv_records', 'caa_records', 'naptr_records', 'sshfp_records', 'ds_records',
                  'loc_records', 'hinfo_records', 'rp_records', 'https_records',)
        read_only_fields = ('id', 'last_modified', 'active')
        write_once_fields = ('zone_root',)

    address_records = AddressRecordSerializer(many=True, read_only=True, source='addressrecord_set')
    dynamic_address_records = DynamicRecordSerializer(many=True, read_only=True, source='dynamicaddressrecord_set')
    aname_records = ANAMERecordSerializer(many=True, read_only=True, source='anamerecord_set')
    cname_records = CNAMERecordSerializer(many=True, read_only=True, source='cnamerecord_set')
    mx_records = MXRecordSerializer(many=True, read_only=True, source='mxrecord_set')
    ns_records = NSRecordSerializer(many=True, read_only=True, source='nsrecord_set')
    txt_records = TXTRecordSerializer(many=True, read_only=True, source='txtrecord_set')
    srv_records = SRVRecordSerializer(many=True, read_only=True, source='srvrecord_set')
    caa_records = CAARecordSerializer(many=True, read_only=True, source='caarecord_set')
    naptr_records = NAPTRRecordSerializer(many=True, read_only=True, source='naptrrecord_set')
    sshfp_records = SSHFPRecordSerializer(many=True, read_only=True, source='sshfprecord_set')
    ds_records = DSRecordSerializer(many=True, read_only=True, source='dsrecord_set')
    loc_records = LOCRecordSerializer(many=True, read_only=True, source='locrecord_set')
    hinfo_records = HINFORecordSerializer(many=True, read_only=True, source='hinforecord_set')
    rp_records = RPRecordSerializer(many=True, read_only=True, source='rprecord_set')
    https_records = HTTPSRecordSerializer(many=True, read_only=True, source='httpsrecord_set')
    dnssec = DNSSECSerializer(read_only=True)

    def to_representation(self, instance):
        ret = super().to_representation(instance)

        dnssec_digest, dnssec_tag = dns_grpc.utils.make_zone_digest(instance.zone_root)
        nums = settings.DNSSEC_PUBKEY.public_numbers()
        pubkey_bytes = nums.x.to_bytes(32, byteorder="big") + nums.y.to_bytes(32, byteorder="big")
        ret["dnssec"] = {
            "key_tag": dnssec_tag,
            "algorithm": 13,
            "digest_type": 2,
            "digest": dnssec_digest,
            "key": {
                "flags": 257,
                "protocol": 3,
                "algorithm": 13,
                "public_key": base64.b64encode(pubkey_bytes)
            }
        }

        return ret


class PTRRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='reverse-ptrrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.ReverseDNSZone)
    zone_url = serializers.HyperlinkedRelatedField(
        source='zone',
        view_name='reversednszone-detail',
        read_only=True,
    )

    class Meta:
        model = models.PTRRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_address', 'pointer', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class ReverseNSRecordSerializer(ZoneRecordSerializer, WriteOnceMixin):
    url = serializers.HyperlinkedIdentityField(
        view_name='reverse-nsrecord-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.ReverseDNSZone)
    zone_url = serializers.HyperlinkedRelatedField(
        source='zone',
        view_name='reversednszone-detail',
        read_only=True,
    )

    class Meta:
        model = models.ReverseNSRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_address', 'record_prefix', 'nameserver', 'ttl',)
        read_only_fields = ('id',)
        write_once_fields = ('zone',)


class ReverseDNSZoneSerializer(WriteOnceMixin, serializers.ModelSerializer):
    class Meta:
        model = models.ReverseDNSZone
        fields = ('url', 'id', 'zone_root_address', 'zone_root_prefix', 'last_modified', 'active', 'ptr_records',
                  'ns_records', 'dnssec')
        read_only_fields = ('id', 'last_modified', 'active')
        write_once_fields = ('zone_root_address', 'zone_root_prefix',)

    ptr_records = PTRRecordSerializer(many=True, read_only=True, source='ptrrecord_set')
    ns_records = ReverseNSRecordSerializer(many=True, read_only=True, source='reversensrecord_set')
    dnssec = DNSSECSerializer(read_only=True)

    def to_representation(self, instance):
        ret = super().to_representation(instance)

        zone_network = ipaddress.ip_network(
            (instance.zone_root_address, instance.zone_root_prefix)
        )
        zone_name = tasks.network_to_apra(zone_network)
        dnssec_digest, dnssec_tag = views.make_zone_digest(zone_name.label)
        nums = settings.DNSSEC_PUBKEY.public_numbers()
        pubkey_bytes = nums.x.to_bytes(32, byteorder="big") + nums.y.to_bytes(32, byteorder="big")
        ret["dnssec"] = {
            "key_tag": dnssec_tag,
            "algorithm": 13,
            "digest_type": 2,
            "digest": dnssec_digest,
            "key": {
                "flags": 257,
                "protocol": 3,
                "algorithm": 13,
                "public_key": base64.b64encode(pubkey_bytes)
            }
        }

        return ret


class SecondaryDNSZoneRecordSerializer(ZoneRecordSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='secondary-record-detail',
        read_only=True,
    )
    zone = PermissionPrimaryKeyRelatedField(model=models.SecondaryDNSZone)
    zone_url = serializers.HyperlinkedRelatedField(
        source='zone',
        view_name='secondarydnszone-detail',
        read_only=True,
    )

    class Meta:
        model = models.SecondaryDNSZoneRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'rtype', 'rdata', 'ttl',)
        read_only_fields = ('id', 'zone', 'record_name', 'rtype', 'rdata', 'ttl',)


class SecondaryDNSZoneSerializer(WriteOnceMixin, serializers.ModelSerializer):
    class Meta:
        model = models.SecondaryDNSZone
        fields = ('url', 'id', 'zone_root', 'primary', 'serial', 'active', 'error', 'records')
        read_only_fields = ('id', 'serial', 'active', 'error')
        write_once_fields = ('zone_root',)

    records = SecondaryDNSZoneRecordSerializer(many=True, read_only=True, source='secondarydnszonerecord_set')


class ImportZoneFileSerializer(serializers.Serializer):
    zone_file = serializers.CharField()
    overwrite = serializers.BooleanField(default=False, required=False)
