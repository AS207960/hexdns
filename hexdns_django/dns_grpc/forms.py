import typing

from django import forms
from . import models
import crispy_forms.helper
import crispy_forms.layout
import crispy_forms.bootstrap
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model


class UserChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return f"{obj.first_name} {obj.last_name} - {obj.email} ({obj.username})"


class AdminZoneForm(forms.Form):
    zone_root = forms.CharField()
    user = UserChoiceField(get_user_model().objects.all())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Create"))


class AdminReverseZoneForm(forms.Form):
    zone_root_address = forms.GenericIPAddressField()
    zone_root_prefix = forms.IntegerField(min_value=0, max_value=128)
    user = UserChoiceField(get_user_model().objects.all())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Create"))


class AdminSecondaryZoneForm(forms.Form):
    zone_root = forms.CharField()
    primary_server = forms.CharField()
    user = UserChoiceField(get_user_model().objects.all())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Create"))


class ZoneForm(forms.Form):
    zone_root = forms.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Create"))


class SecondaryZoneForm(forms.Form):
    zone_root = forms.CharField()
    primary_server = forms.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))


class AddressRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "address", "ttl", "auto_reverse"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.AddressRecord
        fields = "__all__"
        exclude = ("id", "zone")


class DynamicAddressRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password'].disabled = True
        self.fields['password'].required = False
        self.fields['id'].disabled = True
        self.fields['id'].required = False
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "id", "password", "ttl"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DynamicAddressRecord
        fields = "__all__"
        exclude = ("zone", "current_ipv4", "current_ipv6")


class ANAMERecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"), "alias", "ttl"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.ANAMERecord
        fields = "__all__"
        exclude = ("id", "zone")


class RedirectRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "target",
            "include_path",
            "ttl"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.RedirectRecord
        fields = "__all__"
        exclude = ("id", "zone")


class CNAMERecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"), "alias", "ttl"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.CNAMERecord
        fields = "__all__"
        exclude = ("id", "zone")


class MXRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "exchange", "priority", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.MXRecord
        fields = "__all__"
        exclude = ("id", "zone")


class NSRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "nameserver", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.NSRecord
        fields = "__all__"
        exclude = ("id", "zone")


class TXTRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"), "data", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.TXTRecord
        fields = "__all__"
        exclude = ("id", "zone")


class SRVRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "priority", "weight", "port", "target", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.SRVRecord
        fields = "__all__"
        exclude = ("id", "zone")


class CAARecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "flag", "tag", "value", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.CAARecord
        fields = "__all__"
        exclude = ("id", "zone")


class NAPTRRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "order",
            "preference",
            "flags",
            "service",
            "regexp",
            "replacement",
            "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.NAPTRRecord
        fields = "__all__"
        exclude = ("id", "zone")


class SSHFPRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "host_key", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.SSHFPRecord
        fields = "__all__"
        exclude = ("id", "zone")


class DSRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "key_tag", "algorithm", "digest_type", "digest", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DSRecord
        fields = "__all__"
        exclude = ("id", "zone")


class DNSKEYRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "flags", "protocol", "algorithm", "public_key", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DNSKEYRecord
        fields = "__all__"
        exclude = ("id", "zone")


class LOCRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            crispy_forms.layout.Row(
                crispy_forms.layout.Column("latitude"), crispy_forms.layout.Column("longitude")
            ),
            crispy_forms.layout.Row(
                crispy_forms.layout.Column("altitude"), crispy_forms.layout.Column("size")
            ),
            crispy_forms.layout.Row(
                crispy_forms.layout.Column("hp"), crispy_forms.layout.Column("vp")
            ),
            "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.LOCRecord
        fields = "__all__"
        exclude = ("id", "zone")


class HINFORecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "cpu", "os", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.HINFORecord
        fields = "__all__"
        exclude = ("id", "zone")


class RPRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
            "mailbox", "txt", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.RPRecord
        fields = "__all__"
        exclude = ("id", "zone")


class SVCBBaseRecordForm(forms.ModelForm):
    EXTRA_INPUTS: typing.List

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.label_class = 'mt-1'
        self.helper.field_class = 'mb-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.layout.Fieldset(
                "Record name",
                crispy_forms.layout.Div(
                    crispy_forms.layout.Div(
                        crispy_forms.bootstrap.PrependedText("port", "_"),
                        css_class='col-md-3'
                    ),
                    crispy_forms.layout.Div(
                        crispy_forms.bootstrap.PrependedText("scheme", "_"),
                        css_class='col-md-3'
                    ),
                    crispy_forms.layout.Div(
                        crispy_forms.bootstrap.AppendedText("record_name", f".{self.instance.zone.zone_root}"),
                        css_class='col-md-6'
                    ),
                    css_class='row'
                ),
                "ttl"
            ),
            crispy_forms.layout.Fieldset(
                "Target",
                "priority",
                crispy_forms.layout.Div(
                    crispy_forms.layout.Div("target", css_class='col-md-9'),
                    crispy_forms.layout.Div("target_port", css_class='col-md-3'),
                    css_class='row'
                ),
                "target_port_mandatory" if "target_port_mandatory" in self.fields else None,
            ),
            crispy_forms.layout.Fieldset(
                "Scheme specific",
                 *self.EXTRA_INPUTS,
            ),
            crispy_forms.layout.Fieldset(
                "TLS ECH",
                crispy_forms.layout.Field("ech", rows=3),
                "ech_mandatory" if "ech_mandatory" in self.fields else None,
            ),
            crispy_forms.layout.Fieldset(
                "TLS ALPNs",
                crispy_forms.layout.Field("alpns", rows=3),
                "alpn_mandatory" if "alpn_mandatory" in self.fields else None,
                "no_default_alpn",
                "no_default_alpn_mandatory" if "no_default_alpn_mandatory" in self.fields else None,
            ),
            crispy_forms.layout.Fieldset(
                "IP address hints",
                crispy_forms.layout.Field("ipv4_hints", rows=3),
                "ipv4_hints_mandatory" if "ipv4_hints_mandatory" in self.fields else None,
                crispy_forms.layout.Field("ipv6_hints", rows=3),
                "ipv6_hints_mandatory" if "ipv6_hints_mandatory" in self.fields else None,
            ),
            crispy_forms.layout.Fieldset(
                "Misc",
                "extra_params"
            ),
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.SVCBBaseRecord
        fields = "__all__"
        exclude = ("id", "zone")


class HTTPSRecordForm(SVCBBaseRecordForm):
    EXTRA_INPUTS = ("http2_support",)

    class Meta(SVCBBaseRecordForm.Meta):
        model = models.HTTPSRecord


class UpdateSecretForm(forms.ModelForm):
    def __init__(self, *args, has_id=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        if has_id:
            self.fields['id'].disabled = True
            self.fields['id'].required = False
        else:
            del self.fields['id']
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("id", f".{self.instance.zone.zone_root}") if has_id else None,
            "name",
            crispy_forms.bootstrap.AppendedText("restrict_to", f".{self.instance.zone.zone_root}"),
            "type",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DNSZoneUpdateSecrets
        fields = "__all__"
        exclude = ("zone", "secret", "last_used")
        read_only = ("id",)


class AXFRSecretForm(forms.ModelForm):
    def __init__(self, *args, has_id=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        if has_id:
            self.fields['id'].disabled = True
            self.fields['id'].required = False
        else:
            del self.fields['id']
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("id", f".{self.instance.zone.zone_root}") if has_id else None,
            "name"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DNSZoneAXFRSecrets
        fields = "__all__"
        exclude = ("zone", "secret", "last_used")
        read_only = ("id",)


class AXFRIPAClForm(forms.ModelForm):
    def __init__(self, *args, has_id=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        if has_id:
            self.fields['id'].disabled = True
            self.fields['id'].required = False
        else:
            del self.fields['id']
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("id", f".{self.instance.zone.zone_root}") if has_id else None,
            "name",
            "address",
            "prefix"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DNSZoneAXFRIPACL
        fields = "__all__"
        exclude = ("zone", "last_used")
        read_only = ("id",)


class AXFRNotifyForm(forms.ModelForm):
    def __init__(self, *args, has_id=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        if has_id:
            self.fields['id'].disabled = True
            self.fields['id'].required = False
        else:
            del self.fields['id']
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("id", f".{self.instance.zone.zone_root}") if has_id else None,
            "name",
            "server",
            "port"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DNSZoneAXFRNotify
        fields = "__all__"
        exclude = ("zone",)
        read_only = ("id",)


class ReversePTRRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            "record_address", "pointer", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.PTRRecord
        fields = "__all__"
        exclude = ("id", "zone")


class ReverseNSRecordForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            "record_address", "record_prefix", "nameserver", "ttl",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.ReverseNSRecord
        fields = "__all__"
        exclude = ("id", "zone")


class ZoneImportForm(forms.Form):
    zone_data = forms.CharField(widget=forms.Textarea())
    overwrite = forms.BooleanField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-2'
        self.helper.field_class = 'col-lg-10 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.layout.HTML("""
                <div class="alert alert-info" role="alert">
                    Paste a full or partial zone file in RFC 1035 format. We'll ignore any record types we don't support.
                </div>
            """),
            "zone_data",
            "overwrite",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Import"))


class GithubPagesForm(forms.Form):
    record_name = forms.CharField(max_length=255, initial="@", label="Record name (@ for zone root)")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.field_class = 'my-2'
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name",
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Submit"))


class GithubPagesSetupForm(forms.Form):
    record_name = forms.CharField(max_length=255, initial="@", label="Record name (@ for zone root)")
    source_path = forms.ChoiceField(initial="/", label="Source directory", choices=(
        ("/", "/ (root)"),
        ("/docs", "/docs"),
    ))
    source_branch = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            "record_name",
            "source_path",
            "source_branch"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))


class DMARCForm(forms.Form):
    policy = forms.ChoiceField(choices=(
        ("none", "No action"),
        ("quarantine", "Quarantine on fail"),
        ("reject", "Reject on fail")
    ))
    subdomain_policy = forms.ChoiceField(choices=(
        (None, "---"),
        ("none", "No action"),
        ("quarantine", "Quarantine on fail"),
        ("reject", "Reject on fail")
    ), required=False)
    percentage = forms.IntegerField(
        min_value=0, max_value=100, label="Percentage of messages to apply policy to", required=False
    )
    dkim_alignment = forms.ChoiceField(choices=(
        ("r", "Relaxed"),
        ("s", "Strict")
    ), label="DKIM alignment mode")
    spf_alignment = forms.ChoiceField(choices=(
        ("r", "Relaxed"),
        ("s", "Strict")
    ), label="SPF alignment mode")
    report_interval = forms.IntegerField(min_value=0, label="Reporting interval (seconds)", required=False)
    aggregate_feedback = forms.CharField(
        label="Aggregate feedback URIs (example: mailto:dmarc@example.com)", required=False
    )
    failure_feedback = forms.CharField(
        label="Failure information URIs (example: mailto:dmarc@example.com)", required=False
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-3'
        self.helper.field_class = 'col-lg-9 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            "policy",
            "subdomain_policy",
            "percentage",
            "dkim_alignment",
            "spf_alignment",
            "report_interval",
            "aggregate_feedback",
            "failure_feedback"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Generate"))


class ICloudForm(forms.Form):
    record_name = forms.CharField(
        label="Base record name (@ for zone root)", required=True
    )
    verification_txt = forms.CharField(
        label="TXT record starting apple-domain", required=True
    )

    def __init__(self, *args, zone, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            crispy_forms.bootstrap.AppendedText("record_name", f".{zone.zone_root}"),
            "verification_txt"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Setup"))

    def clean_verification_txt(self):
        data = self.cleaned_data['verification_txt']

        if not data.startswith("apple-domain="):
            raise ValidationError("Verification TXT record does not start with apple-domain")

        return data


class AdditionalCDSForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DNSZoneAdditionalCDS
        fields = "__all__"
        exclude = ("dns_zone", "id",)


class AdditionalCDNSKEYForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DNSZoneAdditionalCDNSKEY
        fields = "__all__"
        exclude = ("dns_zone", "id",)


class CustomNSForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = crispy_forms.helper.FormHelper()
        self.helper.use_custom_control = False
        self.helper.form_class = 'form-horizontal'
        self.helper.label_class = 'col-lg-4'
        self.helper.field_class = 'col-lg-8 my-1'
        self.helper.layout = crispy_forms.layout.Layout(
            "nameserver"
        )
        self.helper.add_input(crispy_forms.layout.Submit("submit", "Save"))

    class Meta:
        model = models.DNSZoneCustomNS
        fields = "__all__"
        exclude = ("id", "dns_zone",)
