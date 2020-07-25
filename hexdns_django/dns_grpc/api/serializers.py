from rest_framework import serializers
from rest_framework_nested.relations import NestedHyperlinkedIdentityField
import base64
import ipaddress
from .. import models, views, grpc


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


class ZoneRecordSerializer(WriteOnceMixin, serializers.ModelSerializer):
    zone_url = serializers.HyperlinkedRelatedField(
        view_name='dnszone-detail',
        source='zone',
        read_only=True,
    )


class AddressRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-addressrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.AddressRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'address', 'auto_reverse', 'ttl',)
        read_only_fields = ('id', 'zone')


class DynamicRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-dynamicaddressrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.DynamicAddressRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'current_ipv4', 'current_ipv6', 'password', 'ttl',)
        read_only_fields = ('id', 'zone', 'current_ipv4', 'current_ipv6', 'password')


class ANAMERecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-anamerecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.ANAMERecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'alias', 'ttl',)
        read_only_fields = ('id', 'zone',)


class CNAMERecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-cnamerecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.CNAMERecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'alias', 'ttl',)
        read_only_fields = ('id', 'zone',)


class MXRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-mxrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.MXRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'exchange', 'priority', 'ttl',)
        read_only_fields = ('id', 'zone',)


class NSRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-nsrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.NSRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'nameserver', 'ttl',)
        read_only_fields = ('id', 'zone',)


class TXTRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-txtrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.TXTRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'data', 'ttl',)
        read_only_fields = ('id', 'zone',)


class SRVRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-srvrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.SRVRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'priority', 'weight', 'port', 'target', 'ttl',)
        read_only_fields = ('id', 'zone',)


class CAARecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-caarecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.CAARecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'flag', 'tag', 'value', 'ttl',)
        read_only_fields = ('id', 'zone',)


class NAPTRRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-naptrrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.NAPTRRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'order', 'preference', 'flags', 'service', 'regexp',
                  'replacement', 'ttl',)
        read_only_fields = ('id', 'zone',)


class SSHFPRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-sshfprecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.SSHFPRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'host_key', 'ttl',)
        read_only_fields = ('id', 'zone',)


class DSRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-dsrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.DSRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'key_tag', 'algorithm', 'digest_type', 'digest',
                  'ttl',)
        read_only_fields = ('id', 'zone',)


class LOCRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-locrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.LOCRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'latitude', 'longitude', 'altitude', 'size', 'hp',
                  'vp', 'ttl',)
        read_only_fields = ('id', 'zone',)


class HINFORecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-hinforecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.HINFORecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'cpu', 'os', 'ttl',)
        read_only_fields = ('id', 'zone',)


class RPRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='dnszone-rprecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.RPRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_name', 'mailbox', 'txt', 'ttl',)
        read_only_fields = ('id', 'zone',)


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
                  'loc_records', 'hinfo_records', 'rp_records',)
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
    dnssec = DNSSECSerializer(read_only=True)

    def to_representation(self, instance):
        ret = super().to_representation(instance)

        dnssec_digest, dnssec_tag = views.make_zone_digest(instance.zone_root)
        nums = grpc.pub_key.public_numbers()
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


class PTRRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='reversednszone-ptrrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.PTRRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_address', 'pointer', 'ttl',)
        read_only_fields = ('id', 'zone',)


class ReverseNSRecordSerializer(ZoneRecordSerializer):
    url = NestedHyperlinkedIdentityField(
        view_name='reversednszone-nsrecord-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
    )

    class Meta:
        model = models.ReverseNSRecord
        fields = ('url', 'id', 'zone', 'zone_url', 'record_address', 'record_prefix', 'nameserver', 'ttl',)
        read_only_fields = ('id', 'zone',)


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
        zone_name = grpc.network_to_apra(zone_network)
        dnssec_digest, dnssec_tag = views.make_zone_digest(zone_name.label)
        nums = grpc.pub_key.public_numbers()
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
    url = NestedHyperlinkedIdentityField(
        view_name='secondarydnszone-record-detail',
        lookup_url_kwarg='dnszone_pk',
        read_only=True,
        parent_lookup_kwargs={'dnszone_pk': 'zone__pk', 'pk': 'pk'}
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
